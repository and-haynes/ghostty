import Foundation

// MARK: - Key types

/// The SSH key algorithms the vault can hold.
///
/// swift-nio-ssh implements Ed25519 and the three NIST curves for client
/// authentication, and its `NIOSSHPrivateKey` has a closed set of initialisers
/// with no extension point. **RSA keys can therefore be imported, stored,
/// fingerprinted and exported here but not authenticated with** — see
/// `RSAKey.swift` for the detail. Holding them is still worth doing: pasting
/// the public line into a server's `authorized_keys` is most of what a key
/// manager is for, and refusing the import outright told the user nothing.
enum SSHKeyType: String, Codable, CaseIterable, Identifiable, Sendable {
    case ed25519
    case p256
    case p384
    case p521
    /// P-256 whose private half never leaves the Secure Enclave.
    case secureEnclaveP256
    /// Importable and exportable; cannot yet sign an SSH handshake.
    case rsa

    var id: String { rawValue }

    /// The OpenSSH algorithm name that prefixes an authorized_keys line.
    var opensshName: String {
        switch self {
        case .ed25519: return "ssh-ed25519"
        case .p256, .secureEnclaveP256: return "ecdsa-sha2-nistp256"
        case .p384: return "ecdsa-sha2-nistp384"
        case .p521: return "ecdsa-sha2-nistp521"
        case .rsa: return "ssh-rsa"
        }
    }

    /// The NIST curve identifier embedded in an ECDSA key blob.
    var curveName: String? {
        switch self {
        case .ed25519: return nil
        case .p256, .secureEnclaveP256: return "nistp256"
        case .p384: return "nistp384"
        case .p521: return "nistp521"
        case .rsa: return nil
        }
    }

    var displayName: String {
        switch self {
        case .ed25519: return "Ed25519"
        case .p256: return "ECDSA P-256"
        case .p384: return "ECDSA P-384"
        case .p521: return "ECDSA P-521"
        case .secureEnclaveP256: return "Secure Enclave P-256"
        case .rsa: return "RSA"
        }
    }

    var isSecureEnclave: Bool { self == .secureEnclaveP256 }

    /// Whether a key of this type can authenticate an SSH connection today.
    ///
    /// False only for RSA, and only because swift-nio-ssh cannot sign with it.
    var canAuthenticate: Bool { self != .rsa }

    /// Types offered in the in-app generator. RSA is absent deliberately:
    /// generating a key the app cannot then use would be a trap.
    static var generatable: [SSHKeyType] {
        Self.allCases.filter { $0 != .rsa }
    }
}

// MARK: - Identity

/// A key pair the app can authenticate with.
///
/// Only non-secret metadata lives in this struct; it is persisted as JSON in
/// Application Support. The private half lives in the Keychain under
/// `keychainAccount` and is never serialised here.
struct Identity: Identifiable, Codable, Hashable, Sendable {
    var id: UUID
    var name: String
    var keyType: SSHKeyType
    /// Full OpenSSH `authorized_keys` line: "<algo> <base64> <comment>".
    var publicKeyLine: String
    /// "SHA256:..." in OpenSSH's unpadded-base64 form.
    var fingerprint: String
    var createdAt: Date
    /// True when the private key is a Secure Enclave key reference.
    var isSecureEnclave: Bool
    /// True when the Keychain item is gated by `.biometryCurrentSet`.
    var requiresBiometrics: Bool
    /// True when the Keychain item is marked `kSecAttrSynchronizable`.
    /// Never true for Secure Enclave keys — they cannot leave the device.
    var syncsToICloud: Bool

    var keychainAccount: String { "identity.\(id.uuidString)" }

    init(
        id: UUID = UUID(),
        name: String,
        keyType: SSHKeyType,
        publicKeyLine: String,
        fingerprint: String,
        createdAt: Date = Date(),
        isSecureEnclave: Bool = false,
        requiresBiometrics: Bool = false,
        syncsToICloud: Bool = false
    ) {
        self.id = id
        self.name = name
        self.keyType = keyType
        self.publicKeyLine = publicKeyLine
        self.fingerprint = fingerprint
        self.createdAt = createdAt
        self.isSecureEnclave = isSecureEnclave
        self.requiresBiometrics = requiresBiometrics
        self.syncsToICloud = syncsToICloud
    }
}

// MARK: - Host

/// A saved SSH destination.
struct Host: Identifiable, Codable, Hashable, Sendable {
    var id: UUID
    var alias: String
    var hostname: String
    var port: Int
    var username: String
    /// Identity to authenticate with, or nil to use a stored password.
    var identityID: UUID?
    /// True when a password for this host is (or should be) in the Keychain.
    var usesPassword: Bool
    /// Free-form grouping used by the hosts list's sections.
    var group: String
    var tags: [String]
    /// "#RRGGBB" accent used in the list and the session status bar.
    var colorHex: String?
    /// TERM to request in the pty-req. Remote hosts almost never have
    /// ghostty's terminfo installed, so the default is xterm-256color.
    var term: String
    /// Per-host font size override, in points.
    var fontSize: Double?
    /// Command to run instead of an interactive shell, if any.
    var startupCommand: String?
    var notes: String

    var keychainPasswordAccount: String { "host-password.\(id.uuidString)" }

    init(
        id: UUID = UUID(),
        alias: String = "",
        hostname: String = "",
        port: Int = 22,
        username: String = "",
        identityID: UUID? = nil,
        usesPassword: Bool = false,
        group: String = "Ungrouped",
        tags: [String] = [],
        colorHex: String? = nil,
        term: String = "xterm-256color",
        fontSize: Double? = nil,
        startupCommand: String? = nil,
        notes: String = ""
    ) {
        self.id = id
        self.alias = alias
        self.hostname = hostname
        self.port = port
        self.username = username
        self.identityID = identityID
        self.usesPassword = usesPassword
        self.group = group
        self.tags = tags
        self.colorHex = colorHex
        self.term = term
        self.fontSize = fontSize
        self.startupCommand = startupCommand
        self.notes = notes
    }

    var displayName: String { alias.isEmpty ? "\(username)@\(hostname)" : alias }
    var destination: String { port == 22 ? hostname : "\(hostname):\(port)" }
}

// MARK: - Known hosts

/// A host key pinned on first use.
struct KnownHost: Identifiable, Codable, Hashable, Sendable {
    /// "hostname:port" — the pin is per endpoint, as OpenSSH does it.
    var id: String
    var hostname: String
    var port: Int
    /// OpenSSH algorithm name, e.g. "ssh-ed25519".
    var keyType: String
    /// "SHA256:..." fingerprint of the wire-format key blob.
    var fingerprint: String
    /// "<algo> <base64>" — enough to re-derive the fingerprint and to export.
    var publicKeyLine: String
    var firstSeen: Date

    init(
        hostname: String,
        port: Int,
        keyType: String,
        fingerprint: String,
        publicKeyLine: String,
        firstSeen: Date = Date()
    ) {
        self.id = KnownHost.key(hostname: hostname, port: port)
        self.hostname = hostname
        self.port = port
        self.keyType = keyType
        self.fingerprint = fingerprint
        self.publicKeyLine = publicKeyLine
        self.firstSeen = firstSeen
    }

    static func key(hostname: String, port: Int) -> String { "\(hostname):\(port)" }
}

// MARK: - TOFU

/// The verdict of trust-on-first-use host key checking.
enum TOFUDecision: Equatable, Sendable {
    /// We have a pin and the presented key matches it.
    case trusted(KnownHost)
    /// We have never seen this endpoint. The UI must ask before proceeding.
    case unknown(keyType: String, fingerprint: String, publicKeyLine: String)
    /// We have a pin and the presented key is *different*. Refuse loudly.
    case mismatch(expected: KnownHost, presentedType: String, presentedFingerprint: String)
}

/// Pure TOFU policy, deliberately separated from storage so it is testable
/// without a Keychain or a filesystem.
enum KnownHostsPolicy {
    static func decide(
        existing: KnownHost?,
        presentedType: String,
        presentedFingerprint: String,
        presentedLine: String
    ) -> TOFUDecision {
        guard let existing else {
            return .unknown(
                keyType: presentedType,
                fingerprint: presentedFingerprint,
                publicKeyLine: presentedLine
            )
        }
        if existing.fingerprint == presentedFingerprint && existing.keyType == presentedType {
            return .trusted(existing)
        }
        return .mismatch(
            expected: existing,
            presentedType: presentedType,
            presentedFingerprint: presentedFingerprint
        )
    }
}
