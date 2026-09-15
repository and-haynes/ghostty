import CommonCrypto
import Crypto
import Foundation

// MARK: - Errors

/// Why a bundle could not be produced or read.
///
/// These are separate from `VaultSyncError` on purpose: the provider hands
/// them to the UI unchanged because each one already says something specific
/// and actionable, and wrapping them in `.crypto("…")` ("The vault data could
/// not be decrypted: …") would bury the useful sentence inside a vaguer one.
enum EncryptedBundleError: Error, LocalizedError, Equatable {
    /// The file does not start with the Ghostty bundle magic.
    case notABundle
    /// Right magic, a format this build does not know how to read.
    case unsupportedVersion(UInt8)
    /// Right magic and version, a key-derivation function we don't have.
    case unsupportedKDF(UInt8)
    /// The file stops before the ciphertext and tag do.
    case truncated
    /// The GCM tag did not verify. Wrong passphrase or altered bytes; the
    /// construction cannot tell those apart, and it should not pretend to.
    case wrongPassphraseOrTampered
    case emptyPassphrase
    case keyDerivationFailed(Int32)
    /// The file is not a well-formed bundle payload — either extra bytes
    /// after the end, or a plaintext that decrypted but is not a snapshot.
    case malformedContents(String)

    var errorDescription: String? {
        switch self {
        case .notABundle:
            return "This isn't a Ghostty bundle — the file doesn't start with the Ghostty vault header. "
                + "Pick the .ghosttyvault file you exported."
        case .unsupportedVersion(let version):
            return "This bundle is format version \(version), which this version of Ghostty can't read. "
                + "Update the app, or re-export from the device that wrote it."
        case .unsupportedKDF(let id):
            return "This bundle uses key-derivation method \(id), which this version of Ghostty doesn't "
                + "support. Update the app and try again."
        case .truncated:
            return "This bundle is incomplete — it ends partway through. The copy or download probably "
                + "didn't finish; export it again."
        case .wrongPassphraseOrTampered:
            return "The passphrase is incorrect, or this bundle was written by a newer version of Ghostty "
                + "— or the file has been altered since it was exported."
        case .emptyPassphrase:
            return "A bundle needs a passphrase. It is the only thing protecting the keys inside it."
        case .keyDerivationFailed(let status):
            return "Could not derive a key from the passphrase (error \(status)). "
                + "Try again; if it keeps happening, restart the app."
        case .malformedContents(let detail):
            return "This bundle isn't well-formed: \(detail). Export it again from the device that wrote it."
        }
    }
}

// MARK: - Key derivation

/// The key-derivation functions a bundle may declare.
///
/// An enum with a stored wire id rather than a hardcoded call, so a future
/// build can ship a stronger KDF and still read every bundle already written:
/// the id travels in the header, and `import` dispatches on it.
enum EncryptedBundleKDF: UInt8, Equatable, CaseIterable {
    case pbkdf2HMACSHA256 = 1
    // TODO(#0088B): Argon2id via tmthecoder/Argon2Swift — reserve id 2 for it.
    // Argon2id is the right answer for a passphrase-derived key (PBKDF2 is
    // cheap to attack on a GPU, memory-hardness is the whole point), but it
    // needs a SwiftPM dependency added to project.yml, which this change does
    // not own. PBKDF2 is the shipped path until that lands; bundles written
    // now stay readable afterwards because the header says which was used.

    /// PBKDF2-HMAC-SHA256 iteration count.
    ///
    /// 600 000 is OWASP's current floor for PBKDF2-HMAC-SHA256 (raised from
    /// 310 000 in 2023) and is what an attacker's cost is measured against.
    /// On an A17 this is roughly a third of a second — paid exactly twice per
    /// bundle, at export and at import — so the usual "it's too slow" argument
    /// does not apply here the way it would to a per-request login.
    ///
    /// The number is written into the header rather than assumed on read, so
    /// raising it later does not orphan existing bundles.
    static let pbkdf2Iterations: UInt32 = 600_000

    /// AES-256 needs 32 bytes.
    static let keyLength = 32

    func deriveKey(passphrase: String, salt: [UInt8], iterations: UInt32) throws -> SymmetricKey {
        switch self {
        case .pbkdf2HMACSHA256:
            return try Self.pbkdf2(passphrase: passphrase, salt: salt, iterations: iterations)
        }
    }

    private static func pbkdf2(passphrase: String, salt: [UInt8], iterations: UInt32) throws -> SymmetricKey {
        // CommonCrypto wants a CChar buffer; UTF-8 is the only sane encoding
        // for a passphrase that may contain emoji or accents, and it is what
        // every other implementation uses.
        let password = Array(passphrase.utf8).map { Int8(bitPattern: $0) }
        guard !password.isEmpty else { throw EncryptedBundleError.emptyPassphrase }

        var derived = [UInt8](repeating: 0, count: keyLength)
        let status = password.withUnsafeBufferPointer { passwordBuffer in
            salt.withUnsafeBufferPointer { saltBuffer in
                derived.withUnsafeMutableBufferPointer { output in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.baseAddress,
                        passwordBuffer.count,
                        saltBuffer.baseAddress,
                        saltBuffer.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        output.baseAddress,
                        output.count
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw EncryptedBundleError.keyDerivationFailed(status)
        }

        let key = SymmetricKey(data: Data(derived))
        // SymmetricKey has taken its own locked copy; wipe ours rather than
        // leaving 32 bytes of key material in a heap buffer for the allocator
        // to hand to somebody else.
        for index in derived.indices { derived[index] = 0 }
        return key
    }
}

// MARK: - Bundle

/// One encrypted file holding a whole vault snapshot.
///
/// The escape hatch for every password manager with no API worth talking to.
/// The user exports, moves the file themselves (AirDrop, Files, a USB stick),
/// and imports on the other device. Nothing is uploaded anywhere.
///
/// ## File layout
///
/// All integers big-endian. Byte offsets are absolute.
///
/// ```text
/// offset  size  field
/// ------  ----  -------------------------------------------------------
///      0     8  magic "GHSTYVLT" (ASCII)
///      8     1  format version (currently 1)
///      9     1  KDF id (EncryptedBundleKDF; 1 = PBKDF2-HMAC-SHA256)
///     10     4  KDF iteration count (UInt32)
///     14     1  salt length (16)
///     15     1  nonce length (12)
///     16     4  ciphertext length in bytes, excluding the tag (UInt32)
/// ------------  end of header: 20 bytes, all of it AES-GCM additional data
///     20    16  salt
///     36    12  AES-GCM nonce
///     48     n  ciphertext
///   48+n    16  AES-GCM tag
/// ```
///
/// The plaintext is the JSON encoding of `VaultSnapshot` (ISO-8601 dates,
/// sorted keys — the same convention `Vault` uses on disk, so a record that
/// survives a round trip through a bundle is byte-identical to the one in
/// Application Support). ISO-8601 without fractional seconds means timestamps
/// come back rounded to the second; the only thing that reads `updatedAt` is
/// `VaultSyncMerge`, which needs an ordering and not a precise instant.
///
/// Three deliberate choices:
///
/// - **Magic and version first, in the clear.** Picking the wrong file in the
///   Files browser is the most likely failure by far, and it should say "this
///   isn't a Ghostty bundle" rather than failing a tag check and implying the
///   passphrase was wrong. It costs nothing in confidentiality: the file's
///   name and extension already say what it is.
/// - **The whole header is authenticated data.** The iteration count and the
///   KDF id steer decryption, so they must not be silently editable. Today a
///   tampered iteration count would fail anyway (a different count derives a
///   different key), but the moment a second KDF or a format flag exists, AAD
///   is what stops a downgrade from being accepted as valid.
/// - **A redundant ciphertext length.** The file's own size already implies
///   it, which is exactly why it is worth storing: a half-copied file whose
///   remaining bytes still form a plausible ciphertext-plus-tag would
///   otherwise fail the tag check and be reported as a wrong passphrase. The
///   user would go looking for the wrong problem. With a declared length,
///   "this download didn't finish" is detectable before any crypto runs — and
///   because the header is authenticated, the field cannot be used to lie.
/// - **Random salt and nonce per export.** Two exports of the same vault with
///   the same passphrase produce completely different bytes, so a file sitting
///   in iCloud Drive does not leak "nothing changed since last time" — and,
///   more importantly, GCM nonce reuse under one key is catastrophic.
enum EncryptedBundle {
    static let magic: [UInt8] = Array("GHSTYVLT".utf8)
    static let formatVersion: UInt8 = 1
    static let headerLength = 20
    static let saltLength = 16
    /// AES-GCM's standard nonce size. 96 bits is the only length the security
    /// proof covers without an extra hashing step.
    static let nonceLength = 12
    static let tagLength = 16

    /// The file extension the exporter writes and the Files picker filters on.
    static let fileExtension = "ghosttyvault"

    // MARK: Export

    static func export(_ snapshot: VaultSnapshot, passphrase: String) throws -> Data {
        guard !passphrase.isEmpty else { throw EncryptedBundleError.emptyPassphrase }

        let plaintext: Data
        do {
            plaintext = try encoder().encode(snapshot)
        } catch {
            throw EncryptedBundleError.malformedContents(error.localizedDescription)
        }

        let kdf = EncryptedBundleKDF.pbkdf2HMACSHA256
        let iterations = EncryptedBundleKDF.pbkdf2Iterations
        let salt = randomBytes(saltLength)
        // AES-GCM is a stream cipher mode, so the ciphertext is exactly as long
        // as the plaintext — known before sealing, which matters because the
        // header has to exist first in order to be authenticated.
        let header = makeHeader(kdf: kdf, iterations: iterations, ciphertextLength: plaintext.count)
        let key = try kdf.deriveKey(passphrase: passphrase, salt: salt, iterations: iterations)

        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.seal(
                plaintext,
                using: key,
                nonce: AES.GCM.Nonce(),
                authenticating: Data(header)
            )
        } catch {
            throw EncryptedBundleError.malformedContents("encryption failed: \(error.localizedDescription)")
        }

        var out = Data(header)
        out.append(contentsOf: salt)
        out.append(contentsOf: Array(sealed.nonce))
        out.append(sealed.ciphertext)
        out.append(sealed.tag)
        return out
    }

    // MARK: Import

    static func `import`(_ data: Data, passphrase: String) throws -> VaultSnapshot {
        guard !passphrase.isEmpty else { throw EncryptedBundleError.emptyPassphrase }

        // Normalise to an array once: a `Data` produced by slicing keeps the
        // parent's indices, and absolute offsets into it are a classic source
        // of off-by-a-lot bugs.
        let bytes = [UInt8](data)

        guard bytes.count >= magic.count else { throw EncryptedBundleError.notABundle }
        guard Array(bytes[0..<magic.count]) == magic else { throw EncryptedBundleError.notABundle }
        guard bytes.count >= headerLength else { throw EncryptedBundleError.truncated }

        let version = bytes[8]
        guard version == formatVersion else { throw EncryptedBundleError.unsupportedVersion(version) }

        let kdfID = bytes[9]
        guard let kdf = EncryptedBundleKDF(rawValue: kdfID) else {
            throw EncryptedBundleError.unsupportedKDF(kdfID)
        }

        let iterations = UInt32(bytes[10]) << 24 | UInt32(bytes[11]) << 16
            | UInt32(bytes[12]) << 8 | UInt32(bytes[13])
        guard iterations > 0 else { throw EncryptedBundleError.wrongPassphraseOrTampered }

        // Version 1 fixes both lengths; the bytes are descriptive, not a
        // layout the file gets to redefine. Trusting them would let a crafted
        // file steer our own slicing.
        guard Int(bytes[14]) == saltLength, Int(bytes[15]) == nonceLength else {
            throw EncryptedBundleError.wrongPassphraseOrTampered
        }

        let declaredLength = Int(
            UInt32(bytes[16]) << 24 | UInt32(bytes[17]) << 16 | UInt32(bytes[18]) << 8 | UInt32(bytes[19])
        )
        // A zero-length ciphertext is impossible: the plaintext is always JSON,
        // so anything this short is a damaged file, not an empty vault.
        guard declaredLength > 0 else { throw EncryptedBundleError.wrongPassphraseOrTampered }

        let saltStart = headerLength
        let nonceStart = saltStart + saltLength
        let ciphertextStart = nonceStart + nonceLength
        let expectedCount = ciphertextStart + declaredLength + tagLength

        // Short of the length the file itself declares: the copy or download
        // stopped early. Saying so beats failing the tag check and blaming the
        // passphrase, which is the wrong thing to send the user off to check.
        guard bytes.count >= expectedCount else { throw EncryptedBundleError.truncated }
        guard bytes.count == expectedCount else {
            throw EncryptedBundleError.malformedContents(
                "there are \(bytes.count - expectedCount) unexpected bytes after the end of the bundle"
            )
        }

        let header = Array(bytes[0..<headerLength])
        let salt = Array(bytes[saltStart..<nonceStart])
        let nonceBytes = Array(bytes[nonceStart..<ciphertextStart])
        let tagStart = ciphertextStart + declaredLength
        let ciphertext = Data(bytes[ciphertextStart..<tagStart])
        let tag = Data(bytes[tagStart..<expectedCount])

        let key = try kdf.deriveKey(passphrase: passphrase, salt: salt, iterations: iterations)

        let plaintext: Data
        do {
            let nonce = try AES.GCM.Nonce(data: Data(nonceBytes))
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            plaintext = try AES.GCM.open(box, using: key, authenticating: Data(header))
        } catch {
            // Every failure here — a bad tag, a flipped ciphertext byte, an
            // edited header — is indistinguishable by design, and all of them
            // mean the same thing to the user: this file and this passphrase
            // do not go together. Surfacing CryptoKit's "authenticationFailure"
            // would tell them nothing.
            throw EncryptedBundleError.wrongPassphraseOrTampered
        }

        do {
            return try decoder().decode(VaultSnapshot.self, from: plaintext)
        } catch {
            // Authenticated, so this is our own bug or a future field we don't
            // understand — never an attacker.
            throw EncryptedBundleError.malformedContents(error.localizedDescription)
        }
    }

    // MARK: Header

    static func makeHeader(kdf: EncryptedBundleKDF, iterations: UInt32, ciphertextLength: Int) -> [UInt8] {
        var header = magic
        header.append(formatVersion)
        header.append(kdf.rawValue)
        header.append(contentsOf: bigEndian(iterations))
        header.append(UInt8(saltLength))
        header.append(UInt8(nonceLength))
        header.append(contentsOf: bigEndian(UInt32(truncatingIfNeeded: ciphertextLength)))
        return header
    }

    private static func bigEndian(_ value: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ]
    }

    private static func randomBytes(_ count: Int) -> [UInt8] {
        // SymmetricKey is a convenient wrapper around the system CSPRNG and
        // avoids a SecRandomCopyBytes status code we would have to handle.
        SymmetricKey(size: .init(bitCount: count * 8)).withUnsafeBytes { Array($0) }
    }

    // MARK: JSON

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        // Sorted keys so two exports of an unchanged vault differ only in salt,
        // nonce and ciphertext — not in dictionary ordering.
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    private static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
