import Foundation
import Security

/// RSA keys, backed by Security.framework.
///
/// ## What works, and what does not
///
/// Everything on *this* side of the network works: parsing an RSA key out of
/// any of the four encodings people actually have (SSH wire format, PKCS#1,
/// PKCS#8, `openssh-key-v1`), fingerprinting it, exporting its
/// `authorized_keys` line, signing with it and verifying a signature against
/// it. `SecKey` does the arithmetic; none of it is hand-rolled.
///
/// What does **not** work is using one over an SSH connection, and that is not
/// something this file can fix. swift-nio-ssh 0.15 has no extension point for
/// key types at all:
///
/// * `NIOSSHPublicKey` wraps a `private enum BackingKey` with cases for
///   Ed25519, the three NIST curves and certificates. There is no initialiser
///   that takes an algorithm name and a blob, and no protocol to conform to.
/// * `NIOSSHPrivateKey` is the same shape, with five `public init`s and no
///   sixth.
/// * `SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms` is a
///   hardcoded `static let` of four names, so a server is never even *told*
///   this client would accept an RSA host key.
///
/// So an RSA key can be imported, stored, fingerprinted and exported here — all
/// of which are useful, because pasting the public line into a server's
/// `authorized_keys` is most of what people want from a key manager — but
/// authenticating with it needs a patched or vendored copy of the library. The
/// UI says so plainly rather than refusing the import and leaving the user
/// guessing.
enum RSASignatureAlgorithm: String, CaseIterable, Sendable {
    /// SHA-1. Accepted for *verification* only, because it is what old servers
    /// present and refusing to read one is not the same as refusing to use it.
    case sshRSA = "ssh-rsa"
    case sha256 = "rsa-sha2-256"
    case sha512 = "rsa-sha2-512"

    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .sshRSA: return .rsaSignatureMessagePKCS1v15SHA1
        case .sha256: return .rsaSignatureMessagePKCS1v15SHA256
        case .sha512: return .rsaSignatureMessagePKCS1v15SHA512
        }
    }

    /// Whether this app will *produce* a signature with it. SHA-1 is read-only.
    var isUsableForSigning: Bool { self != .sshRSA }
}

enum RSAKeyError: Error, Equatable, LocalizedError {
    case malformed(String)
    case unsupportedKeySize(Int)
    case securityFramework(String)
    case cannotDeriveCRTExponents

    var errorDescription: String? {
        switch self {
        case .malformed(let detail):
            return "This does not look like a valid RSA key. \(detail)"
        case .unsupportedKeySize(let bits):
            return """
                A \(bits)-bit RSA key is too small to be safe. Use at least 2048 bits \
                (`ssh-keygen -t rsa -b 4096`), or an Ed25519 key.
                """
        case .securityFramework(let detail):
            return "The system rejected this RSA key: \(detail)"
        case .cannotDeriveCRTExponents:
            return """
                This RSA key is missing the values needed to rebuild it — its primes \
                do not divide as expected. The file is probably damaged.
                """
        }
    }
}

// MARK: - Public half

struct RSAPublicKey {
    let secKey: SecKey
    /// Big-endian, minimally encoded.
    let modulus: Data
    let exponent: Data

    var bitCount: Int { self.modulus.count * 8 }

    /// The SSH wire format: `string("ssh-rsa") || mpint(e) || mpint(n)`.
    ///
    /// Note the order — exponent first, then modulus — which is the opposite of
    /// every other encoding RSA appears in, and a reliable source of keys that
    /// parse but do not verify.
    var sshBlob: Data {
        OpenSSHWire.writeString("ssh-rsa")
            + OpenSSHWire.writeMPInt(self.exponent)
            + OpenSSHWire.writeMPInt(self.modulus)
    }

    /// PKCS#1 `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`.
    var pkcs1DER: Data {
        DER.sequence([DER.integer(self.modulus), DER.integer(self.exponent)])
    }

    var fingerprint: String { SSHFingerprint.sha256(blob: self.sshBlob) }

    func publicKeyLine(comment: String) -> String {
        let base = "ssh-rsa \(self.sshBlob.base64EncodedString())"
        let trimmed = comment.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? base : "\(base) \(trimmed)"
    }

    init(modulus: Data, exponent: Data) throws {
        let n = Self.trimmed(modulus)
        let e = Self.trimmed(exponent)
        guard !n.isEmpty, !e.isEmpty else {
            throw RSAKeyError.malformed("The modulus or exponent is empty.")
        }
        guard n.count * 8 >= 1024 else { throw RSAKeyError.unsupportedKeySize(n.count * 8) }

        let der = DER.sequence([DER.integer(n), DER.integer(e)])
        var error: Unmanaged<CFError>?
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: n.count * 8,
        ]
        guard
            let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error)
        else {
            throw RSAKeyError.securityFramework(Self.describe(&error))
        }
        self.secKey = key
        self.modulus = n
        self.exponent = e
    }

    init(secKey: SecKey) throws {
        var error: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw RSAKeyError.securityFramework(Self.describe(&error))
        }
        var reader = DER.Reader(try DER.contents(of: .sequence, in: external))
        let n = try reader.readInteger()
        let e = try reader.readInteger()
        self.secKey = secKey
        self.modulus = Self.trimmed(n)
        self.exponent = Self.trimmed(e)
    }

    /// Parse `string("ssh-rsa") || mpint(e) || mpint(n)`, the blob inside an
    /// `authorized_keys` line or a host key.
    init(sshBlob: Data) throws {
        var reader = OpenSSHWireReader(sshBlob)
        guard let name = reader.readStringUTF8() else {
            throw RSAKeyError.malformed("The algorithm name is missing.")
        }
        // Servers announce rsa-sha2-256 / rsa-sha2-512 but the *key* blob still
        // says "ssh-rsa": the sha2 names select a signature algorithm, not a
        // key type (RFC 8332 §3).
        guard name == "ssh-rsa" else {
            throw RSAKeyError.malformed("Expected an ssh-rsa key, found \"\(name)\".")
        }
        guard let e = reader.readString(), let n = reader.readString() else {
            throw RSAKeyError.malformed("The exponent or modulus is missing.")
        }
        try self.init(modulus: n, exponent: e)
    }

    /// Parse PKCS#1 `RSAPublicKey`.
    init(pkcs1DER: Data) throws {
        var reader = DER.Reader(try DER.contents(of: .sequence, in: pkcs1DER))
        let n = try reader.readInteger()
        let e = try reader.readInteger()
        try self.init(modulus: n, exponent: e)
    }

    func isValidSignature(
        _ signature: Data,
        for message: Data,
        algorithm: RSASignatureAlgorithm
    ) -> Bool {
        var error: Unmanaged<CFError>?
        let valid = SecKeyVerifySignature(
            self.secKey,
            algorithm.secKeyAlgorithm,
            message as CFData,
            signature as CFData,
            &error
        )
        error?.release()
        return valid
    }

    fileprivate static func trimmed(_ data: Data) -> Data {
        var bytes = [UInt8](data)
        while bytes.count > 1, bytes.first == 0 { bytes.removeFirst() }
        return Data(bytes)
    }

    fileprivate static func describe(_ error: inout Unmanaged<CFError>?) -> String {
        guard let error else { return "no reason given" }
        let message = CFErrorCopyDescription(error.takeUnretainedValue()) as String? ?? "unknown"
        error.release()
        return message
    }
}

// MARK: - Private half

struct RSAPrivateKey {
    let secKey: SecKey
    let publicKey: RSAPublicKey

    /// PKCS#1 `RSAPrivateKey`, which is what `SecKeyCopyExternalRepresentation`
    /// gives back and what the Keychain stores.
    var pkcs1DER: Data {
        var error: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(self.secKey, &error) as Data? else {
            error?.release()
            return Data()
        }
        return external
    }

    init(secKey: SecKey) throws {
        guard let publicHalf = SecKeyCopyPublicKey(secKey) else {
            throw RSAKeyError.malformed("The key has no public half.")
        }
        self.secKey = secKey
        self.publicKey = try RSAPublicKey(secKey: publicHalf)
    }

    /// PKCS#1 `RSAPrivateKey` — the body of a `-----BEGIN RSA PRIVATE KEY-----`
    /// file, and what Security.framework wants.
    init(pkcs1DER: Data) throws {
        // Validate the shape before handing it over, so a malformed file gets
        // our message rather than an opaque OSStatus.
        var reader = DER.Reader(try DER.contents(of: .sequence, in: pkcs1DER))
        let version = try reader.readInteger()
        guard version == Data([0]) || version.isEmpty else {
            throw RSAKeyError.malformed("Multi-prime RSA keys are not supported.")
        }
        let modulus = try reader.readInteger()
        guard modulus.count * 8 >= 1024 else {
            throw RSAKeyError.unsupportedKeySize(modulus.count * 8)
        }

        var error: Unmanaged<CFError>?
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: modulus.count * 8,
        ]
        guard
            let key = SecKeyCreateWithData(pkcs1DER as CFData, attributes as CFDictionary, &error)
        else {
            throw RSAKeyError.securityFramework(RSAPublicKey.describe(&error))
        }
        try self.init(secKey: key)
    }

    /// Rebuild a key from the six values `openssh-key-v1` stores.
    ///
    /// OpenSSH writes `n, e, d, iqmp, p, q`. PKCS#1 additionally wants the CRT
    /// exponents `d mod (p-1)` and `d mod (q-1)`, which OpenSSH does not store
    /// because it recomputes them — so we recompute them too. That is the whole
    /// reason `BigUnsignedInteger` exists.
    init(modulus n: Data, exponent e: Data, privateExponent d: Data, prime1 p: Data,
         prime2 q: Data, coefficient iqmp: Data) throws {
        guard let pMinusOne = BigUnsignedInteger.decrement(p),
            let qMinusOne = BigUnsignedInteger.decrement(q),
            let dP = BigUnsignedInteger.modulo(d, pMinusOne),
            let dQ = BigUnsignedInteger.modulo(d, qMinusOne)
        else {
            throw RSAKeyError.cannotDeriveCRTExponents
        }

        let der = DER.sequence([
            DER.integer(Data([0])),
            DER.integer(n),
            DER.integer(e),
            DER.integer(d),
            DER.integer(p),
            DER.integer(q),
            DER.integer(dP),
            DER.integer(dQ),
            DER.integer(iqmp),
        ])
        try self.init(pkcs1DER: der)
    }

    func signature(for message: Data, algorithm: RSASignatureAlgorithm) throws -> Data {
        guard algorithm.isUsableForSigning else {
            throw RSAKeyError.malformed(
                "ssh-rsa (SHA-1) signatures are accepted for verification but never produced."
            )
        }
        var error: Unmanaged<CFError>?
        guard
            let signature = SecKeyCreateSignature(
                self.secKey,
                algorithm.secKeyAlgorithm,
                message as CFData,
                &error
            ) as Data?
        else {
            throw RSAKeyError.securityFramework(RSAPublicKey.describe(&error))
        }
        return signature
    }
}
