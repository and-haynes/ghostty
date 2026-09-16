import Foundation

/// Why a handshake could not be negotiated, in words a person can act on.
///
/// `NIOSSHError.keyExchangeNegotiationFailure` is the entire diagnosis
/// swift-nio-ssh offers when a client and a server share no algorithm. It does
/// not say which of the four negotiations failed, what the server wanted, or
/// what the client could have done — and the four have completely different
/// fixes. This type does the comparison the library did and reports it.
///
/// Pure and testable: hand it a recorded `SSHServerOffer` and it produces the
/// same text it would for a live host.
struct SSHAlgorithmMismatch: Equatable {
    /// Which negotiation had an empty intersection. Ordered the way the
    /// protocol negotiates them, because the first failure is the one to fix.
    enum Category: String, CaseIterable, Equatable {
        case keyExchange = "key exchange"
        case hostKey = "host key"
        case cipher = "cipher"
        case mac = "MAC"
    }

    let hostname: String
    let offer: SSHServerOffer

    let supportedKeyExchange: [String]
    let supportedHostKeys: [String]
    let supportedCiphers: [String]
    let supportedMACs: [String]

    /// What both sides can do, in the client's preference order. An empty list
    /// is a failed negotiation.
    let keyExchangeInCommon: [String]
    let hostKeysInCommon: [String]
    let ciphersInCommon: [String]
    let macsInCommon: [String]

    init(
        hostname: String,
        offer: SSHServerOffer,
        supportedKeyExchange: [String] = SSHAlgorithmSupport.keyExchangeAlgorithms,
        // What a client with *no* certificate authority configured offers,
        // which is the conservative answer and the common case. A caller that
        // has a CA passes the wider list — otherwise this would report a
        // certificate-only server as negotiable when it is not.
        supportedHostKeys: [String] = SSHAlgorithmSupport.plainHostKeyAlgorithms,
        supportedCiphers: [String] = SSHAlgorithmSupport.ciphers,
        supportedMACs: [String] = SSHAlgorithmSupport.macs
    ) {
        self.hostname = hostname
        self.offer = offer
        self.supportedKeyExchange = supportedKeyExchange
        self.supportedHostKeys = supportedHostKeys
        self.supportedCiphers = supportedCiphers
        self.supportedMACs = supportedMACs

        func common(_ ours: [String], _ theirs: [String]) -> [String] {
            let peer = Set(theirs)
            return ours.filter { peer.contains($0) }
        }
        self.keyExchangeInCommon = common(supportedKeyExchange, offer.keyExchangeAlgorithms)
        self.hostKeysInCommon = common(supportedHostKeys, offer.hostKeyAlgorithms)
        self.ciphersInCommon = common(supportedCiphers, offer.ciphers)
        // An AEAD cipher ignores MAC negotiation entirely, so a MAC mismatch
        // only matters when the surviving ciphers all need one.
        self.macsInCommon = common(supportedMACs, offer.macs)
    }

    /// The negotiations with nothing in common, in protocol order.
    var failures: [Category] {
        var result: [Category] = []
        if keyExchangeInCommon.isEmpty { result.append(.keyExchange) }
        if hostKeysInCommon.isEmpty { result.append(.hostKey) }
        if ciphersInCommon.isEmpty { result.append(.cipher) }
        // Only a real failure if every usable cipher needs a MAC. The OpenSSH
        // GCM modes and chacha20-poly1305 carry their own tag.
        if macsInCommon.isEmpty, !ciphersInCommon.isEmpty,
            ciphersInCommon.allSatisfy({ Self.requiresSeparateMAC($0) })
        {
            result.append(.mac)
        }
        return result
    }

    var canNegotiate: Bool { failures.isEmpty }

    /// One line for a status bar or an alert title.
    var summary: String {
        guard let first = failures.first else {
            return "\(hostname) and Ghostty can negotiate a connection."
        }
        if failures.count == 1 {
            return "No \(first.rawValue) algorithm in common with \(hostname)."
        }
        let names = failures.map(\.rawValue).joined(separator: ", ")
        return "No \(names) algorithm in common with \(hostname)."
    }

    /// The whole explanation: what the server offered, what this app supports,
    /// what is missing, and — where there is one — the fix.
    var explanation: String {
        var lines: [String] = []
        lines.append(summary)
        lines.append("")
        if !offer.banner.isEmpty {
            lines.append("It says it is: \(offer.banner)")
        }
        for line in offer.preamble where !line.isEmpty {
            lines.append("It also said: \(line)")
        }
        if !offer.banner.isEmpty || !offer.preamble.isEmpty {
            lines.append("")
        }

        lines.append("\(hostname) offers")
        lines.append(Self.row("host keys", offer.hostKeyAlgorithms))
        lines.append(Self.row("ciphers", offer.ciphers))
        lines.append(Self.row("key exchange", offer.keyExchangeAlgorithms))
        lines.append(Self.row("MACs", offer.macs))
        lines.append("")
        lines.append("Ghostty supports")
        lines.append(Self.row("host keys", supportedHostKeys))
        lines.append(Self.row("ciphers", supportedCiphers))
        lines.append(Self.row("key exchange", supportedKeyExchange))
        lines.append(Self.row("MACs", supportedMACs))

        guard !failures.isEmpty else {
            lines.append("")
            lines.append("Nothing is missing — this handshake should succeed.")
            return lines.joined(separator: "\n")
        }

        lines.append("")
        lines.append("Missing: \(failures.map(\.rawValue).joined(separator: ", ")).")
        for advice in self.advice {
            lines.append("")
            lines.append(advice)
        }
        return lines.joined(separator: "\n")
    }

    /// Concrete next steps for the mismatches we recognise.
    var advice: [String] {
        var notes: [String] = []

        if failures.contains(.hostKey) {
            // Ghostty verifies Ed25519, the three NIST curves, RSA (SHA-2 only)
            // and an OpenSSH certificate over any of them, so reaching this
            // branch means either that no certificate authority is configured
            // for a host that presents nothing but certificates, or that the
            // server offers something genuinely outside that set — `ssh-dss`, or
            // `ssh-rsa` with no SHA-2 variant alongside it.
            let certificateOnly = !offer.hostKeyAlgorithms.isEmpty
                && offer.hostKeyAlgorithms.allSatisfy { Self.isCertificate($0) }
            let sha1RSAOnly = !offer.hostKeyAlgorithms.isEmpty
                && offer.hostKeyAlgorithms.allSatisfy { $0 == "ssh-rsa" }
            let dssOnly = !offer.hostKeyAlgorithms.isEmpty
                && offer.hostKeyAlgorithms.allSatisfy { $0 == "ssh-dss" }

            if certificateOnly {
                notes.append(
                    """
                    \(hostname) only presents CA-signed host certificates, and Ghostty has no \
                    certificate authority to check one against — so it does not ask for one, \
                    and the two of you have no host key algorithm in common.

                    Add the CA's public key (the contents of its .pub file) under \
                    Settings › SSH certificates. Alternatively, on the server: keep a plain \
                    Ed25519 host key alongside the certificate — OpenSSH offers both by \
                    default, so something has removed the plain HostKey line here.
                    """
                )
            } else if sha1RSAOnly {
                notes.append(
                    """
                    \(hostname) offers its RSA host key under ssh-rsa only, which signs \
                    with SHA-1. Ghostty will verify an RSA host key, but only under \
                    rsa-sha2-256 or rsa-sha2-512 — OpenSSH itself has refused SHA-1 \
                    since 8.8, and offering to accept it would undo the point of asking \
                    for SHA-2.

                    On the server: add rsa-sha2-512,rsa-sha2-256 to HostKeyAlgorithms \
                    (any OpenSSH from 7.2 supports them), or add an Ed25519 host key \
                    with ssh-keygen -A.
                    """
                )
            } else if dssOnly {
                notes.append(
                    """
                    \(hostname)'s only host key is DSA (ssh-dss), which is 1024-bit by \
                    definition and which OpenSSH itself removed in version 9.8. Ghostty \
                    does not implement it.

                    On the server: generate a modern host key with ssh-keygen -A and \
                    add a HostKey /etc/ssh/ssh_host_ed25519_key line to sshd_config.
                    """
                )
            } else {
                notes.append(
                    """
                    Enable an Ed25519, ECDSA or RSA (rsa-sha2-*) host key on \(hostname). \
                    Ghostty cannot verify any other kind.
                    """
                )
            }
        }

        if failures.contains(.keyExchange) {
            let hasDiffieHellman = offer.keyExchangeAlgorithms.contains {
                $0.hasPrefix("diffie-hellman-")
            }
            if hasDiffieHellman {
                notes.append(
                    """
                    \(hostname) offers only finite-field Diffie-Hellman key exchange, \
                    which swift-nio-ssh does not implement. Add curve25519-sha256 to \
                    the server's KexAlgorithms.
                    """
                )
            } else {
                notes.append(
                    "Add curve25519-sha256 to \(hostname)'s KexAlgorithms."
                )
            }
        }

        if failures.contains(.cipher) {
            notes.append(
                """
                Add aes256-ctr (or an aes*-gcm@openssh.com or \
                chacha20-poly1305@openssh.com mode) to \(hostname)'s Ciphers.
                """
            )
        }

        if failures.contains(.mac) {
            notes.append(
                """
                Add hmac-sha2-256-etm@openssh.com (or hmac-sha2-256, or \
                hmac-sha2-512) to \(hostname)'s MACs.
                """
            )
        }

        return notes
    }

    // MARK: - Helpers

    private static func row(_ label: String, _ names: [String]) -> String {
        let padded = label.padding(toLength: 14, withPad: " ", startingAt: 0)
        return "  \(padded)\(names.isEmpty ? "(none)" : names.joined(separator: ", "))"
    }

    /// True for ciphers that negotiate a MAC separately, i.e. everything that
    /// is not an AEAD.
    static func requiresSeparateMAC(_ cipher: String) -> Bool {
        !cipher.hasSuffix("-gcm@openssh.com") && cipher != "chacha20-poly1305@openssh.com"
    }

    /// OpenSSH host and user certificates.
    static func isCertificate(_ algorithm: String) -> Bool {
        algorithm.hasSuffix("-cert-v01@openssh.com")
    }
}
