import Foundation
import Security
// swift-crypto re-exports CryptoKit on Apple platforms. Importing `Crypto`
// rather than `CryptoKit` keeps these key types identical to the ones
// swift-nio-ssh's `NIOSSHPrivateKey` initialisers expect; mixing the two
// modules produces "cannot convert P256.Signing.PrivateKey to
// P256.Signing.PrivateKey" errors that read like a compiler bug.
import Crypto

/// A private key the vault can authenticate with.
///
/// The Secure Enclave case is deliberately a separate case rather than a flag:
/// its private half is a hardware reference, not bytes, so anything that wants
/// to export or re-encode a key has to acknowledge that it cannot.
enum SSHPrivateKeyMaterial {
    case ed25519(Curve25519.Signing.PrivateKey)
    case p256(P256.Signing.PrivateKey)
    case p384(P384.Signing.PrivateKey)
    case p521(P521.Signing.PrivateKey)
    case secureEnclaveP256(SecureEnclave.P256.Signing.PrivateKey)

    var keyType: SSHKeyType {
        switch self {
        case .ed25519: return .ed25519
        case .p256: return .p256
        case .p384: return .p384
        case .p521: return .p521
        case .secureEnclaveP256: return .secureEnclaveP256
        }
    }

    var isSecureEnclave: Bool {
        if case .secureEnclaveP256 = self { return true }
        return false
    }

    // MARK: - Public half

    /// The wire-format public key: what gets base64'd into an authorized_keys
    /// line, and what the SHA256 fingerprint is taken over.
    ///
    ///   ed25519: string("ssh-ed25519") || string(32-byte point)
    ///   ecdsa:   string(algo) || string(curve) || string(0x04 || X || Y)
    var publicKeyBlob: Data {
        switch self {
        case .ed25519(let key):
            return OpenSSHWire.writeString(SSHKeyType.ed25519.opensshName)
                + OpenSSHWire.writeString(key.publicKey.rawRepresentation)
        case .p256(let key):
            return Self.ecdsaBlob(type: .p256, point: key.publicKey.x963Representation)
        case .p384(let key):
            return Self.ecdsaBlob(type: .p384, point: key.publicKey.x963Representation)
        case .p521(let key):
            return Self.ecdsaBlob(type: .p521, point: key.publicKey.x963Representation)
        case .secureEnclaveP256(let key):
            // An SE key is a plain nistp256 key on the wire — the server has
            // no idea (and no need to know) where the private half lives.
            return Self.ecdsaBlob(type: .secureEnclaveP256, point: key.publicKey.x963Representation)
        }
    }

    private static func ecdsaBlob(type: SSHKeyType, point: Data) -> Data {
        // `curveName` is non-nil for every ECDSA case; the empty fallback keeps
        // this total instead of force-unwrapping an enum invariant.
        OpenSSHWire.writeString(type.opensshName)
            + OpenSSHWire.writeString(type.curveName ?? "")
            + OpenSSHWire.writeString(point)
    }

    /// An `authorized_keys` line. The comment is omitted when empty rather
    /// than left as a trailing space, which some strict parsers reject.
    func publicKeyLine(comment: String) -> String {
        let base = "\(keyType.opensshName) \(publicKeyBlob.base64EncodedString())"
        let trimmed = comment.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? base : "\(base) \(trimmed)"
    }

    var fingerprint: String { SSHFingerprint.sha256(blob: publicKeyBlob) }

    // MARK: - Generation

    /// Whether this device can hold a hardware-backed key at all. Exposed here
    /// so callers (and tests) can ask without importing CryptoKit themselves.
    static var isSecureEnclaveAvailable: Bool { SecureEnclave.isAvailable }

    static func generate(_ type: SSHKeyType, requiresBiometrics: Bool) throws -> SSHPrivateKeyMaterial {
        switch type {
        case .ed25519: return .ed25519(Curve25519.Signing.PrivateKey())
        case .p256: return .p256(P256.Signing.PrivateKey())
        case .p384: return .p384(P384.Signing.PrivateKey())
        case .p521: return .p521(P521.Signing.PrivateKey())
        case .secureEnclaveP256:
            // The simulator has no Secure Enclave. Fail with a sentence the UI
            // can show verbatim instead of trapping inside CryptoKit.
            guard SecureEnclave.isAvailable else { throw VaultError.secureEnclaveUnavailable }
            guard requiresBiometrics else {
                return .secureEnclaveP256(try SecureEnclave.P256.Signing.PrivateKey())
            }
            let control = try Self.biometricPrivateKeyAccessControl()
            return .secureEnclaveP256(
                try SecureEnclave.P256.Signing.PrivateKey(accessControl: control)
            )
        }
    }

    /// `.biometryCurrentSet` rather than `.biometryAny`: enrolling a new face
    /// or finger invalidates the key, so an attacker who adds their own
    /// biometric to an unlocked device cannot then use the key.
    private static func biometricPrivateKeyAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        let control = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        )
        if let error { error.release() }
        guard let control else { throw KeychainError.accessControlFailed }
        return control
    }

    // MARK: - Persistence

    /// The bytes stored in the Keychain for this key.
    ///
    /// For software keys this is the private scalar/seed. For a Secure Enclave
    /// key it is the opaque, device-bound blob the Enclave hands back — useless
    /// on any other device, which is exactly the property we want.
    var persistableData: Data {
        switch self {
        case .ed25519(let key): return key.rawRepresentation
        case .p256(let key): return key.rawRepresentation
        case .p384(let key): return key.rawRepresentation
        case .p521(let key): return key.rawRepresentation
        case .secureEnclaveP256(let key): return key.dataRepresentation
        }
    }

    static func restore(type: SSHKeyType, data: Data) throws -> SSHPrivateKeyMaterial {
        do {
            switch type {
            case .ed25519:
                return .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: data))
            case .p256:
                return .p256(try P256.Signing.PrivateKey(rawRepresentation: data))
            case .p384:
                return .p384(try P384.Signing.PrivateKey(rawRepresentation: data))
            case .p521:
                return .p521(try P521.Signing.PrivateKey(rawRepresentation: data))
            case .secureEnclaveP256:
                guard SecureEnclave.isAvailable else { throw VaultError.secureEnclaveUnavailable }
                return .secureEnclaveP256(
                    try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
                )
            }
        } catch let error as VaultError {
            throw error
        } catch {
            // CryptoKit's errors ("incorrectKeySize") mean nothing to a user
            // staring at a key they just imported.
            throw VaultError.malformedKey(
                "Stored \(type.displayName) key material could not be reloaded (\(data.count) bytes)."
            )
        }
    }
}
