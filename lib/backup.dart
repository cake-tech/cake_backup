/// This library is useful for safely encrypting and decrypting data with a passphrase.
/// 
/// Since user-supplied passphrases are assumed to be of low entropy (and probably reused elsewhere), we run the passphrase through a password-based key derivation function (PBKDF) using a random salt.
/// The resulting derived key is used with a random nonce to encrypt the data with an authenticated encryption with additional data (AEAD) construction, which also provides authentication.
/// After this process, we assemble a plaintext protocol version number, the PBKDF salt, and all AEAD data.
/// A checksum is computed over this assembled data and appended to it; this is useful for fast detection of data that may have been incompletely or incorrectly transferred across devices.
/// 
/// To decrypt, we parse the data into its expected components: protocol version number, PBKDF salt, AEAD data, checksum.
/// The protocol version number and checksum are first verified, in order to abort early in case of an unsupported version or corrupted data.
/// The supplied passphrase is then used with the PBKDF salt to derive the key.
/// This key is used with the AEAD data to authenticate the ciphertext; we abort if this fails, as the data has been tampered with and is invalid.
/// If authentication succeeds, we decrypt and return the plaintext.
/// 
/// You can specify a version for encryption, but the library will safely default to the most recent.
/// Decryption automatically detects and supports all known versions.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:tuple/tuple.dart';

/// Utility function to securely generate random bytes
Uint8List randomBytes(int number) {
  Random rng = Random.secure();
  return Uint8List.fromList(List<int>.generate(number, (_) => rng.nextInt(0xFF + 1)));
}

/// Get version information
/// NOTE: A new version _must_ have a higher number than all previous versions, as this determines the default
List<VersionParameters> getAllVersions() {
  List<VersionParameters> versions = [];
  const String protocol = 'Cake Wallet backup v';
  int version;
  String aad;

  // Version 1 is the legacy system, which is outside of this library's control
  // NOTE: Downgrade attacks may be possible because of this

  // Version 2 uses PBKDF2, ChaCha20-Poly1305, and Blake2
  // NOTE: We use a random AEAD nonce, which in general can be _unsafe_ for ChaCha20-Poly1305; however, a new PBKDF key is derived on each encryption, so it's safe in this specific design
  version = 2;
  aad = protocol + version.toString();
  const int owaspRecommendedPbkdf2Sha512Iterations = 120000; // OWASP recommendation: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
  const int pbkdf2SaltLength = 16; // Take that, rainbow tables!
  versions.add(VersionParameters(
    version,
    (passphrase, salt) => _pbkdf2(passphrase, salt,  Hmac.sha512(), owaspRecommendedPbkdf2Sha512Iterations, Cryptography.instance.chacha20Poly1305Aead().secretKeyLength),
    (key, nonce, plaintext) => _chaCha20Poly1305Encrypt(key, nonce, plaintext, aad),
    (key, nonce, blob, tag) => _chaCha20Poly1305Decrypt(key, nonce, blob, tag, aad),
    (data) => _blake2b(data, aad),
    pbkdf2SaltLength,
    Cryptography.instance.chacha20Poly1305Aead().nonceLength,
    Poly1305().macLength,
    Blake2b().hashLengthInBytes
  ));

  return versions;
}

/// Get parameters for a version
VersionParameters getVersion(int? version) {
  // Get all versions
  final List<VersionParameters> versions = getAllVersions();

  // If no version is specified, use the highest
  version ??= versions.map((version) => version.version).reduce(max);

  // Return the (first) version with this number if it exists
  final VersionParameters foundVersion = versions.firstWhere((item) => item.version == version, orElse: () => throw BadProtocolVersion());
  return foundVersion;
}

/// An exception indicating incomplete data
class BadDataLength implements Exception {
  String errMsg() => 'The backup file is corrupted and could not be recovered (error code: BadDataLength).';
}

/// An exception indicating an unsupported protocol version
class BadProtocolVersion implements Exception {
  String errMsg() => 'The backup file uses a version that this software does not understand (error code: BadProtocolVersion).';
}

/// An exception indicating failed decryption
class FailedDecryption implements Exception {
  String errMsg() => 'The backup file is corrupted and could not be recovered (error code: FailedDecryption).';
}

/// An exception indicating a bad checksum
class BadChecksum implements Exception {
  String errMsg() => 'The backup file is corrupted and could not be recovered (error code: BadChecksum).';
}

/// An exception indicating a bad AAD length
class BadAadLength implements Exception {
  String errMsg() => 'There was an unexpected internal error (error code: BadAadLength).';
}

/// Class to hold data relevant for decryption
class PackageData {
  VersionParameters parameters;
  Uint8List pbkdfSalt;
  Uint8List aeadNonce;
  Uint8List aeadTag;
  Uint8List ciphertext;

  PackageData(this.parameters, this.pbkdfSalt, this.aeadNonce, this.aeadTag, this.ciphertext);

  /// Encode data to bytes
  Uint8List encode(Uint8List checksum) {
    if (checksum.length != parameters.checksumSize) {
      throw BadChecksum();
    }

    final BytesBuilder bytes = BytesBuilder();
    bytes.addByte(parameters.version);
    bytes.add(pbkdfSalt);
    bytes.add(aeadNonce);
    bytes.add(aeadTag);
    bytes.add(checksum);
    bytes.add(ciphertext);
    return bytes.toBytes();
  }
}

/// Class to hold data for protocol versions
class VersionParameters {
  int version;
  Future<Uint8List> Function(String, Uint8List) pbkdf; // (passphrase, salt) -> (derived_key)
  Future<Tuple2<Uint8List, Uint8List>> Function(Uint8List, Uint8List, Uint8List) aeadEncrypt; // (key, nonce, plaintext) -> (ciphertext, tag)
  Future<Uint8List> Function(Uint8List, Uint8List, Uint8List, Uint8List) aeadDecrypt; // (key, nonce, blob, tag) -> (plaintext)
  Future<Uint8List> Function(PackageData) checksum; // (data)
  int pbkdfSaltSize; // PBKDF salt size in bytes
  int aeadNonceSize; // AEAD nonce size in bytes
  int aeadTagSize; // AEAD tag size in bytes
  int checksumSize; // checksum size in bytes

  VersionParameters(
    this.version,
    this.pbkdf,
    this.aeadEncrypt,
    this.aeadDecrypt,
    this.checksum,
    this.pbkdfSaltSize,
    this.aeadNonceSize,
    this.aeadTagSize,
    this.checksumSize,
  );
}

/// Parse data from bytes
Future<PackageData> _parseBytes(Uint8List bytes) async {
  // We need to parse at least the version
  if (bytes.isEmpty) {
    throw BadDataLength();
  }

  // Keep a counter for indexing purposes, because Dart iterators are silly
  int i = 0;

  // Parse the version and ensure it's valid; this can fail
  final VersionParameters parameters = getVersion(bytes[0]);
  i += 1;

  // Use the version to determine the minimum length of the bytes
  if (bytes.length < 1 + parameters.pbkdfSaltSize + parameters.aeadNonceSize + parameters.aeadTagSize + parameters.checksumSize) {
    throw BadDataLength();
  }

  // Since we know that we have enough bytes, parse all the required data
  final Uint8List pbkdfNonce = bytes.sublist(i, i + parameters.pbkdfSaltSize);
  i += parameters.pbkdfSaltSize;
  final Uint8List aeadNonce = bytes.sublist(i, i + parameters.aeadNonceSize);
  i += parameters.aeadNonceSize;
  final Uint8List aeadTag = bytes.sublist(i, i + parameters.aeadTagSize);
  i += parameters.aeadTagSize;
  final Uint8List checksum = bytes.sublist(i, i + parameters.checksumSize);
  i += parameters.checksumSize;
  final Uint8List ciphertext = bytes.sublist(i);

  // Verify the checksum
  final PackageData data = PackageData(parameters, pbkdfNonce, aeadNonce, aeadTag, ciphertext);
  final Uint8List expectedChecksum = await parameters.checksum(data);
  if (!(const ListEquality()).equals(checksum, expectedChecksum)) {
    throw BadChecksum();
  }

  return data;
}

//
// PBKDF functions
//

/// PBKDF2
Future<Uint8List> _pbkdf2(String passphrase, Uint8List nonce, MacAlgorithm macAlgorithm, int iterations, int derivedKeyLength) async {
  final pbkdf = Pbkdf2(
    macAlgorithm: macAlgorithm,
    iterations: iterations,
    bits: derivedKeyLength * 8 // bits
  );
  final SecretKey secKey = await pbkdf.deriveKey(
    secretKey: SecretKey(utf8.encode(passphrase)),
    nonce: nonce.toList()
  );
  final bytes = await secKey.extractBytes();
  return Uint8List.fromList(bytes);
}

//
// AEAD functions
//

/// ChaCha20-Poly1305 encryption
Future<Tuple2<Uint8List, Uint8List>> _chaCha20Poly1305Encrypt(Uint8List key, Uint8List nonce, Uint8List plaintext, String aad) async {
  final SecretBox box = await Cryptography.instance.chacha20Poly1305Aead().encrypt(
    plaintext.toList(),
    secretKey: SecretKey(key.toList()),
    nonce: nonce,
    aad: utf8.encode(aad)
  );

  final Uint8List ciphertext = Uint8List.fromList(box.cipherText);
  final Uint8List tag = Uint8List.fromList(box.mac.bytes);

  return Tuple2<Uint8List, Uint8List>(ciphertext, tag);
}

/// ChaCha20-Poly1305 decryption
Future<Uint8List> _chaCha20Poly1305Decrypt(Uint8List key, Uint8List nonce, Uint8List blob, Uint8List tag, String aad) async {
  try {
    final List<int> plaintext = await Cryptography.instance.chacha20Poly1305Aead().decrypt(
      SecretBox(
        blob.toList(),
        nonce: nonce,
        mac: Mac(tag)),
      secretKey: SecretKey(key),
      aad: utf8.encode(aad)
    );

    return Uint8List.fromList(plaintext);
  } catch(_) {
    throw FailedDecryption();
  }
}

//
// Checksums
//

// Blake2b
Future<Uint8List> _blake2b(PackageData data, String aad) async {
  // Get a one-byte encoding of the AAD length
  if (aad.length > 0xFF) {
    throw BadAadLength();
  }
  
  final HashSink streamer = Blake2b().newHashSink();
  streamer.add(<int>[aad.length]);
  streamer.add(utf8.encode(aad));
  streamer.add(<int>[data.parameters.version]);
  streamer.add(data.pbkdfSalt);
  streamer.add(data.aeadNonce);
  streamer.add(data.aeadTag);
  streamer.add(data.ciphertext);
  streamer.close();
  final Hash checksum = await streamer.hash();

  return Future<Uint8List>(() => Uint8List.fromList(checksum.bytes));
}

//
// API functions
//

/// Encrypt data with a passphrase and return the raw data structure and checksum (useful for testing)
Future<Tuple2<PackageData, Uint8List>> encryptRaw(String passphrase, Uint8List plaintext, {int? version}) async {
  // Get version parameters; this can fail
  final VersionParameters parameters = getVersion(version);

  // Use the PBKDF to derive an AEAD key from the passphrase
  final Uint8List pbkdfSalt = randomBytes(parameters.pbkdfSaltSize);
  final Uint8List derivedKey = await parameters.pbkdf(passphrase, pbkdfSalt);
  
  // Use the AEAD to encrypt the plaintext
  final Uint8List aeadNonce = randomBytes(parameters.aeadNonceSize);
  final Tuple2<Uint8List, Uint8List> ciphertext = await parameters.aeadEncrypt(derivedKey, aeadNonce, plaintext); // (blob, tag)

  // Assemble data and add the checksum
  final PackageData data = PackageData(parameters, pbkdfSalt, aeadNonce, ciphertext.item2, ciphertext.item1);
  final Uint8List checksum = await parameters.checksum(data);

  // Encode and return the data
  return Tuple2<PackageData, Uint8List>(data, checksum);
}

/// Encrypt data with a passphrase and return the encoded data
Future<Uint8List> encrypt(String passphrase, Uint8List plaintext, {int? version}) async {
  final Tuple2<PackageData, Uint8List> raw = await encryptRaw(passphrase, plaintext, version: version);
  final PackageData data = raw.item1;
  final Uint8List checksum = raw.item2;

  return data.encode(checksum);
}

// Decrypt data with a passphrase
Future<Uint8List> decrypt(String passphrase, Uint8List bytes) async {
  // Parse the bytes into data; this can fail
  final PackageData data = await _parseBytes(bytes);

  // Use the PBKDF to derive an AEAD key from the passphrase
  final Uint8List derivedKey = await data.parameters.pbkdf(passphrase, data.pbkdfSalt);

  // Use the AEAD to authenticate and decrypt the plaintext; this can fail
  final Uint8List plaintext = await data.parameters.aeadDecrypt(derivedKey, data.aeadNonce, data.ciphertext, data.aeadTag);

  return Uint8List.fromList(plaintext);
}
