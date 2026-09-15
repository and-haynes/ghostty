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
        supportedHostKeys: [String] = SSHAlgorithmSupport.hostKeyAlgorithms,
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
            let rsaOnly = offer.hostKeyAlgorithms.allSatisfy { Self.isRSA($0) }
            if rsaOnly && !offer.hostKeyAlgorithms.isEmpty {
                notes.append(
                    """
                    \(hostname)'s only host keys are RSA. The SSH library this app is \
                    built on (swift-nio-ssh 0.15) has a closed set of host key types — \
                    Ed25519 and the three NIST curves — and no way to add RSA from \
                    outside it, so this is not something Ghostty can work around.

                    On the server: generate an Ed25519 host key and offer it, with \
                    ssh-keygen -A and a HostKey /etc/ssh/ssh_host_ed25519_key line in \
                    sshd_config. Appliances that cannot do that (older routers, some \
                    NAS firmware) cannot be reached from this app.
                    """
                )
            } else {
                notes.append(
                    """
                    Enable an Ed25519 or ECDSA host key on \(hostname). Ghostty cannot \
                    verify any other kind.
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
            let longKeyOnly = offer.ciphers.allSatisfy {
                SSHAlgorithmSupport.longKeyCiphers.contains($0)
                    || $0 == "chacha20-poly1305@openssh.com"
            }
            if longKeyOnly && !offer.ciphers.isEmpty {
                notes.append(Self.longKeyNote)
            } else {
                notes.append(
                    """
                    Add aes256-ctr (or an aes*-gcm@openssh.com mode) to \(hostname)'s \
                    Ciphers.
                    """
                )
            }
        }

        if failures.contains(.mac) {
            let sha512Only = offer.macs.allSatisfy { $0.hasPrefix("hmac-sha2-512") }
            if sha512Only && !offer.macs.isEmpty {
                notes.append(Self.longKeyNote)
            } else {
                notes.append(
                    """
                    Add hmac-sha2-256-etm@openssh.com (or hmac-sha2-256) to \
                    \(hostname)'s MACs.
                    """
                )
            }
        }

        return notes
    }

    /// The one explanation nobody would guess: implemented, tested, and still
    /// unusable because of how the library derives keys.
    private static let longKeyNote = """
        The only algorithms this server will accept need a 64-byte session key. \
        Ghostty implements them, but swift-nio-ssh 0.15 derives session keys by \
        truncating a single key-exchange hash rather than expanding it, so it can \
        only produce 64 bytes when the key exchange is ecdh-sha2-nistp521 — and \
        this server did not offer that. Adding ecdh-sha2-nistp521 to the server's \
        KexAlgorithms, or adding aes256-ctr with hmac-sha2-256, fixes it from the \
        server side.
        """

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

    static func isRSA(_ algorithm: String) -> Bool {
        algorithm == "ssh-rsa" || algorithm.hasPrefix("rsa-sha2-")
            || algorithm == "ssh-rsa-cert-v01@openssh.com"
    }
}
