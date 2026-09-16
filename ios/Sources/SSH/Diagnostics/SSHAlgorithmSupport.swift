import Foundation
import NIOSSH

/// What this app can actually negotiate, and why.
///
/// The key exchange and host key lists are swift-nio-ssh's, hardcoded inside
/// the library with no extension point; the cipher and MAC lists are ours,
/// from ``SSHTransportProtectionCatalog``. Keeping them in one place means the
/// mismatch explainer, the Test connection sheet and the README cannot drift
/// apart from what the code does.
enum SSHAlgorithmSupport {
    /// swift-nio-ssh's key exchange preference order, and the digest each one
    /// hashes to.
    ///
    /// The digest size used to be a hard ceiling on session key material,
    /// because the library truncated one hash rather than expanding it. It no
    /// longer is (#008D0), but the sizes are still what the diagnostics report
    /// and what `SSHTransportProtectionCatalog.schemes(keyExchangeHashBytes:)`
    /// would consult if a future scheme needed more than an exchange can give.
    static let keyExchange: [(name: String, hashBytes: Int)] = [
        ("ecdh-sha2-nistp384", 48),
        ("ecdh-sha2-nistp256", 32),
        ("ecdh-sha2-nistp521", 64),
        ("curve25519-sha256", 32),
        ("curve25519-sha256@libssh.org", 32),
    ]

    static var keyExchangeAlgorithms: [String] { Self.keyExchange.map(\.name) }

    /// Host key algorithms this client offers, in preference order.
    ///
    /// This mirrors `SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms`
    /// in the fork, which is what actually goes into KEXINIT. Certificates come
    /// first, as they do in OpenSSH, so a host that has one presents it; the
    /// plain algorithms follow for every host that does not.
    ///
    /// The RSA entries are signature algorithm names, not key formats: RFC 8332
    /// §3 reuses the `ssh-rsa` key blob for both. `ssh-rsa` itself is absent
    /// because it signs with SHA-1; the fork will verify one if a server insists
    /// on sending it, but this client never asks.
    static let hostKeyAlgorithms: [String] = certificateHostKeyAlgorithms + plainHostKeyAlgorithms

    /// CA-signed host certificates, offered only when a certificate authority is
    /// configured — see ``offeredHostKeyAlgorithms(trustingCertificateAuthorities:)``.
    static let certificateHostKeyAlgorithms: [String] = [
        "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com",
        "rsa-sha2-256-cert-v01@openssh.com",
    ]

    static let plainHostKeyAlgorithms: [String] = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ]

    /// What this client actually names in KEXINIT.
    ///
    /// Asking for a host certificate we have no CA for would be worse than not
    /// asking: the server would present one, we would have nothing to check it
    /// against, and a connection that worked yesterday under trust-on-first-use
    /// would start failing. So the certificate algorithms are offered only when
    /// there is a CA to judge them with, and certificates come first when they
    /// are — that is how OpenSSH orders them, and it is what lets a certified
    /// host present its certificate while an uncertified one falls back to its
    /// plain key in the same negotiation.
    static func offeredHostKeyAlgorithms(trustingCertificateAuthorities: Bool) -> [String] {
        trustingCertificateAuthorities
            ? Self.certificateHostKeyAlgorithms + Self.plainHostKeyAlgorithms
            : Self.plainHostKeyAlgorithms
    }

    static var ciphers: [String] { SSHTransportProtectionCatalog.cipherNames() }
    static var macs: [String] { SSHTransportProtectionCatalog.macNames() }

    /// The key exchange that would be chosen against this server, and the
    /// number of bytes of key material it can produce.
    ///
    /// RFC 4253 §7.1: the algorithm is the first on the *client's* list that
    /// the server also names, which is what makes this predictable from the
    /// server's KEXINIT alone.
    static func negotiatedKeyExchange(with offer: SSHServerOffer) -> (name: String, hashBytes: Int)? {
        let serverSupports = Set(offer.keyExchangeAlgorithms)
        return Self.keyExchange.first { serverSupports.contains($0.name) }
    }

    /// Compression is the one negotiation this app cannot influence:
    /// swift-nio-ssh offers `none` only. A server configured with
    /// `Compression yes` still offers `none`, so this is almost never the
    /// problem — but when it is, saying so saves an afternoon.
    static let compression: [String] = ["none"]
}
