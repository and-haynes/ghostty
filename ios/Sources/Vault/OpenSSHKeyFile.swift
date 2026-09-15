import Foundation
import Crypto

// MARK: - Errors

/// Failures the vault surfaces to the user. Every `errorDescription` is
/// written to be shown verbatim in an alert, so it says what went wrong *and*
/// what to do about it.
enum VaultError: Error, LocalizedError, Equatable {
    case encryptedKeyUnsupported
    case unsupportedKeyType(String)
    case malformedKey(String)
    case secureEnclaveUnavailable
    case cannotExportSecureEnclaveKey
    case identityNotFound
    case duplicateName(String)

    var errorDescription: String? {
        switch self {
        case .encryptedKeyUnsupported:
            return """
            This private key is passphrase-encrypted, which Ghostty cannot open yet. \
            Decrypt a copy first with:  ssh-keygen -p -N "" -f key
            """
        case .unsupportedKeyType(let name):
            return """
            "\(name)" keys are not supported. Ghostty can use Ed25519 and ECDSA \
            P-256/P-384/P-521 keys; RSA is not supported by the SSH library it is built on.
            """
        case .malformedKey(let detail):
            return "This does not look like a valid OpenSSH private key. \(detail)"
        case .secureEnclaveUnavailable:
            return """
            This device has no Secure Enclave, so a hardware-backed key cannot be created. \
            (The iOS Simulator never has one — use a regular key there.)
            """
        case .cannotExportSecureEnclaveKey:
            return """
            Secure Enclave keys cannot be exported — their private half never leaves the \
            chip, which is the reason to use one. Copy the public key instead.
            """
        case .identityNotFound:
            return "That key is no longer in the vault."
        case .duplicateName(let name):
            return "A key named \"\(name)\" already exists. Pick a different name."
        }
    }
}

// MARK: - Fingerprints

/// OpenSSH's `SHA256:` fingerprint form, as printed by `ssh-keygen -l`.
enum SSHFingerprint {
    /// SHA-256 of the wire-format public key blob, base64'd with the `=`
    /// padding stripped — OpenSSH omits it, so keeping it would make our
    /// strings fail a naive comparison against what the user sees in a
    /// terminal.
    static func sha256(blob: Data) -> String {
        let digest = Data(SHA256.hash(data: blob))
        let encoded = digest.base64EncodedString().replacingOccurrences(of: "=", with: "")
        return "SHA256:" + encoded
    }

    /// Fingerprint an `authorized_keys`/`known_hosts`-style line:
    /// "<algo> <base64> [comment]". Returns nil if field 1 is missing or is
    /// not valid base64.
    static func sha256(publicKeyLine: String) -> String? {
        let fields = publicKeyLine.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard fields.count >= 2, let blob = Data(base64Encoded: String(fields[1])) else {
            return nil
        }
        return sha256(blob: blob)
    }
}

// MARK: - openssh-key-v1 container

/// Reader/writer for the `-----BEGIN OPENSSH PRIVATE KEY-----` container.
///
/// Layout (PROTOCOL.key in the OpenSSH source):
///
///   "openssh-key-v1\0"
///   string  ciphername
///   string  kdfname
///   string  kdfoptions
///   uint32  number of keys        (always 1 in practice)
///   string  publickey blob
///   string  encrypted/plain private section
///
/// and inside the private section:
///
///   uint32  checkint
///   uint32  checkint              (equal to the first — the passphrase check)
///   string  keytype
///   ...     per-algorithm key fields
///   string  comment
///   bytes   1, 2, 3, ... padding to the cipher block size
enum OpenSSHKeyFile {
    private static let magic = Data("openssh-key-v1\0".utf8)
    private static let beginMarker = "-----BEGIN OPENSSH PRIVATE KEY-----"
    private static let endMarker = "-----END OPENSSH PRIVATE KEY-----"
    /// The "none" cipher still pads to an 8-byte block.
    private static let paddingBlockSize = 8
    private static let pemLineLength = 70

    // MARK: Parse

    static func parse(pem: String) throws -> (material: SSHPrivateKeyMaterial, comment: String) {
        let container = try decodePEM(pem)
        var reader = OpenSSHWireReader(container)

        guard let magicBytes = reader.readBytes(magic.count), magicBytes == magic else {
            throw VaultError.malformedKey("The openssh-key-v1 header is missing.")
        }
        guard let cipherName = reader.readStringUTF8(),
              let kdfName = reader.readStringUTF8(),
              reader.readString() != nil,          // kdfoptions, empty when unencrypted
              let keyCount = reader.readUInt32(),
              reader.readString() != nil,          // public key blob; re-derived below
              let privateSection = reader.readString()
        else {
            throw VaultError.malformedKey("The key header is truncated.")
        }

        // Check this before anything else: an encrypted key is the single most
        // likely import failure and deserves its own actionable message.
        guard cipherName == "none", kdfName == "none" else {
            throw VaultError.encryptedKeyUnsupported
        }
        guard keyCount == 1 else {
            throw VaultError.malformedKey("The file holds \(keyCount) keys; expected exactly one.")
        }

        var priv = OpenSSHWireReader(privateSection)
        guard let check1 = priv.readUInt32(), let check2 = priv.readUInt32() else {
            throw VaultError.malformedKey("The private section is truncated.")
        }
        guard check1 == check2 else {
            // With cipher "none" a mismatch means corruption, not a bad
            // passphrase — there is no passphrase to be wrong.
            throw VaultError.malformedKey("The private section failed its integrity check.")
        }
        guard let keyTypeName = priv.readStringUTF8() else {
            throw VaultError.malformedKey("The key algorithm name is missing.")
        }

        let material = try readPrivateKey(typeName: keyTypeName, from: &priv)

        guard let comment = priv.readStringUTF8() else {
            throw VaultError.malformedKey("The key comment is missing.")
        }
        try validatePadding(priv.remaining)

        return (material, comment)
    }

    private static func readPrivateKey(
        typeName: String,
        from reader: inout OpenSSHWireReader
    ) throws -> SSHPrivateKeyMaterial {
        switch typeName {
        case SSHKeyType.ed25519.opensshName:
            // ed25519 stores pub(32) then priv(64), where priv = seed || pub.
            guard let publicPoint = reader.readString(), let secret = reader.readString() else {
                throw VaultError.malformedKey("The Ed25519 key fields are truncated.")
            }
            guard publicPoint.count == 32, secret.count == 64 else {
                throw VaultError.malformedKey(
                    "Unexpected Ed25519 field sizes (\(publicPoint.count)/\(secret.count) bytes)."
                )
            }
            let seed = secret.prefix(32)
            guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else {
                throw VaultError.malformedKey("The Ed25519 private scalar is invalid.")
            }
            guard key.publicKey.rawRepresentation == publicPoint else {
                throw VaultError.malformedKey("The Ed25519 public and private halves do not match.")
            }
            return .ed25519(key)

        case SSHKeyType.p256.opensshName, SSHKeyType.p384.opensshName, SSHKeyType.p521.opensshName:
            guard let type = ecdsaType(forName: typeName) else {
                throw VaultError.unsupportedKeyType(typeName)
            }
            guard let curve = reader.readStringUTF8(),
                  let publicPoint = reader.readString(),
                  let scalarMPInt = reader.readString()
            else {
                throw VaultError.malformedKey("The ECDSA key fields are truncated.")
            }
            guard curve == type.curveName else {
                throw VaultError.malformedKey(
                    "Key algorithm \(typeName) does not match its embedded curve \"\(curve)\"."
                )
            }
            guard let scalar = OpenSSHWire.mpintToFixedWidth(
                scalarMPInt,
                byteCount: scalarByteCount(type)
            ) else {
                throw VaultError.malformedKey("The ECDSA private scalar is the wrong size.")
            }
            let material = try makeECDSA(type: type, scalar: scalar)
            // Cross-check the stored point against the one we derive; a
            // mismatch means a corrupt file we should reject now rather than
            // at authentication time against a real server.
            guard derivedPoint(material) == publicPoint else {
                throw VaultError.malformedKey("The ECDSA public and private halves do not match.")
            }
            return material

        default:
            throw VaultError.unsupportedKeyType(typeName)
        }
    }

    // MARK: Encode

    static func encode(material: SSHPrivateKeyMaterial, comment: String) throws -> String {
        var privateSection = Data()
        // The checkint is a random 32-bit value written twice; on decryption a
        // mismatch means the passphrase was wrong. We write unencrypted keys,
        // so it is only ever a corruption check — but it must still be random,
        // not a constant, so encrypting our output later stays sound.
        let checkint = UInt32.random(in: UInt32.min...UInt32.max)
        privateSection += OpenSSHWire.writeUInt32(checkint)
        privateSection += OpenSSHWire.writeUInt32(checkint)
        privateSection += OpenSSHWire.writeString(material.keyType.opensshName)

        switch material {
        case .ed25519(let key):
            let publicPoint = key.publicKey.rawRepresentation
            privateSection += OpenSSHWire.writeString(publicPoint)
            privateSection += OpenSSHWire.writeString(key.rawRepresentation + publicPoint)
        case .p256(let key):
            privateSection += ecdsaPrivateFields(
                type: .p256,
                point: key.publicKey.x963Representation,
                scalar: key.rawRepresentation
            )
        case .p384(let key):
            privateSection += ecdsaPrivateFields(
                type: .p384,
                point: key.publicKey.x963Representation,
                scalar: key.rawRepresentation
            )
        case .p521(let key):
            privateSection += ecdsaPrivateFields(
                type: .p521,
                point: key.publicKey.x963Representation,
                scalar: key.rawRepresentation
            )
        case .secureEnclaveP256:
            throw VaultError.cannotExportSecureEnclaveKey
        }

        privateSection += OpenSSHWire.writeString(comment)
        // Pad with 1, 2, 3, ... to the cipher block size.
        let padCount = (paddingBlockSize - privateSection.count % paddingBlockSize) % paddingBlockSize
        if padCount > 0 {
            privateSection += Data((1...padCount).map { UInt8($0) })
        }

        var container = magic
        container += OpenSSHWire.writeString("none")   // ciphername
        container += OpenSSHWire.writeString("none")   // kdfname
        container += OpenSSHWire.writeString(Data())   // kdfoptions
        container += OpenSSHWire.writeUInt32(1)        // nkeys
        container += OpenSSHWire.writeString(material.publicKeyBlob)
        container += OpenSSHWire.writeString(privateSection)

        return encodePEM(container)
    }

    private static func ecdsaPrivateFields(type: SSHKeyType, point: Data, scalar: Data) -> Data {
        OpenSSHWire.writeString(type.curveName ?? "")
            + OpenSSHWire.writeString(point)
            + OpenSSHWire.writeMPInt(scalar)
    }

    // MARK: PEM framing

    private static func decodePEM(_ pem: String) throws -> Data {
        let lines = pem.split(whereSeparator: \.isNewline).map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        guard let begin = lines.firstIndex(of: beginMarker),
              let end = lines.lastIndex(of: endMarker),
              begin < end
        else {
            throw VaultError.malformedKey(
                "Expected a file starting with \"\(beginMarker)\". PEM \"RSA PRIVATE KEY\" and "
                + "PuTTY .ppk files are different formats."
            )
        }
        let body = lines[(begin + 1)..<end].joined()
        guard !body.isEmpty, let data = Data(base64Encoded: body) else {
            throw VaultError.malformedKey("The base64 body is empty or not decodable.")
        }
        return data
    }

    private static func encodePEM(_ data: Data) -> String {
        let body = data.base64EncodedString()
        var lines = [beginMarker]
        var index = body.startIndex
        while index < body.endIndex {
            let next = body.index(index, offsetBy: pemLineLength, limitedBy: body.endIndex)
                ?? body.endIndex
            lines.append(String(body[index..<next]))
            index = next
        }
        lines.append(endMarker)
        // OpenSSH key files end with a newline; some tools reject one that does not.
        return lines.joined(separator: "\n") + "\n"
    }

    // MARK: Helpers

    private static func validatePadding(_ padding: Data) throws {
        guard padding.count < paddingBlockSize else {
            throw VaultError.malformedKey("Trailing data after the key comment.")
        }
        for (offset, byte) in padding.enumerated() where byte != UInt8(offset + 1) {
            throw VaultError.malformedKey("The private section padding is corrupt.")
        }
    }

    private static func ecdsaType(forName name: String) -> SSHKeyType? {
        switch name {
        case SSHKeyType.p256.opensshName: return .p256
        case SSHKeyType.p384.opensshName: return .p384
        case SSHKeyType.p521.opensshName: return .p521
        default: return nil
        }
    }

    private static func scalarByteCount(_ type: SSHKeyType) -> Int {
        switch type {
        case .p256, .secureEnclaveP256: return 32
        case .p384: return 48
        case .p521: return 66   // 521 bits rounded up
        case .ed25519: return 32
        }
    }

    private static func makeECDSA(type: SSHKeyType, scalar: Data) throws -> SSHPrivateKeyMaterial {
        do {
            switch type {
            case .p256: return .p256(try P256.Signing.PrivateKey(rawRepresentation: scalar))
            case .p384: return .p384(try P384.Signing.PrivateKey(rawRepresentation: scalar))
            case .p521: return .p521(try P521.Signing.PrivateKey(rawRepresentation: scalar))
            default: throw VaultError.unsupportedKeyType(type.opensshName)
            }
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError.malformedKey("The ECDSA private scalar is not a valid \(type.displayName) key.")
        }
    }

    private static func derivedPoint(_ material: SSHPrivateKeyMaterial) -> Data? {
        switch material {
        case .p256(let key): return key.publicKey.x963Representation
        case .p384(let key): return key.publicKey.x963Representation
        case .p521(let key): return key.publicKey.x963Representation
        case .ed25519(let key): return key.publicKey.rawRepresentation
        case .secureEnclaveP256(let key): return key.publicKey.x963Representation
        }
    }
}
