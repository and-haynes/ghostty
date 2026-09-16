import Foundation
import NIOCore
import NIOSSH

/// An OpenSSH certificate — the thing `ssh-keygen -s` produces, and the second
/// half of what makes a CA-enrolled fleet work.
///
/// A certificate is a public key plus a CA's signature over a set of claims: who
/// the key belongs to, which principals it may log in as, how long it is good
/// for, and what it is allowed to do. A server that trusts the CA does not need
/// to know the key. That is the whole point: enrol a new phone by signing its
/// key once, rather than by editing `authorized_keys` on every host.
///
/// ## Where the parsing happens
///
/// The wire format (`PROTOCOL.certkeys` in the OpenSSH source) is parsed by
/// swift-nio-ssh, which has a tested implementation of it. This type is a
/// display-and-validation layer over `NIOSSHCertifiedPublicKey`: the vault
/// stores certificates as their `authorized_keys`-style text and stays free of
/// NIO, and everything that needs to know what is *in* one comes through here.
struct SSHCertificate: Sendable, Equatable {
    /// What a certificate is for. A user certificate authenticates a person to a
    /// host; a host certificate authenticates a host to a person. Accepting one
    /// where the other is meant would turn a CA's power to enrol users into the
    /// power to impersonate hosts, which is why the distinction is checked.
    enum Kind: String, Sendable {
        case user
        case host
        case unknown
    }

    /// The certificate as it appears in a file: `"<type> <base64> [comment]"`.
    let line: String
    let comment: String?

    let kind: Kind
    /// The CA's free-text label for this certificate, shown by `ssh-keygen -L`
    /// as "Key ID". Usually an identity: `andy@morton`.
    let keyID: String
    let serial: UInt64
    /// Usernames (user certificates) or hostnames (host certificates) this
    /// certificate is valid for. Empty means "any", which is how OpenSSH encodes
    /// a certificate with no `-n`.
    let principals: [String]
    /// nil when the certificate is valid from the beginning of time.
    let validAfter: Date?
    /// nil when the certificate never expires (`ssh-keygen -V always:forever`).
    let validBefore: Date?
    let extensions: [String]
    let criticalOptions: [String: String]
    /// SHA256 fingerprint of the CA key that signed this certificate.
    let authorityFingerprint: String?
    /// SHA256 fingerprint of the key being certified — the same fingerprint the
    /// identity that owns this certificate shows.
    let certifiedKeyFingerprint: String?

    /// The parsed key, for handing to NIOSSH.
    let certifiedKey: NIOSSHCertifiedPublicKey

    static func == (lhs: SSHCertificate, rhs: SSHCertificate) -> Bool {
        lhs.certifiedKey == rhs.certifiedKey
    }
}

enum SSHCertificateError: Error, Equatable, LocalizedError {
    case notACertificate(String)
    case malformed(String)
    case wrongKey(certificateFingerprint: String, keyFingerprint: String)

    var errorDescription: String? {
        switch self {
        case .notACertificate(let found):
            return """
                That is a \(found), not a certificate. A certificate line starts with a type \
                ending in -cert-v01@openssh.com, and is what ssh-keygen -s writes to \
                <key>-cert.pub.
                """
        case .malformed(let detail):
            return "This certificate could not be read. \(detail)"
        case .wrongKey(let certificateFingerprint, let keyFingerprint):
            return """
                This certificate is for a different key. It certifies \(certificateFingerprint), \
                and this identity is \(keyFingerprint). Sign this key with your CA, or import \
                the certificate onto the key it belongs to.
                """
        }
    }
}

extension SSHCertificate {
    /// Parses an OpenSSH certificate line.
    ///
    /// Accepts the whole file `ssh-keygen -s` writes, whitespace and trailing
    /// newline included, because that is what lands on the clipboard.
    static func parse(_ text: String) throws -> SSHCertificate {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let fields = trimmed.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard let type = fields.first.map(String.init), fields.count >= 2 else {
            throw SSHCertificateError.malformed("It should be a type, a base64 blob and an optional comment.")
        }

        guard type.hasSuffix("-cert-v01@openssh.com") else {
            throw SSHCertificateError.notACertificate(type.isEmpty ? "blank line" : "\(type) public key")
        }

        let line = "\(type) \(fields[1])"
        let comment = fields.count > 2 ? String(fields[2]).trimmingCharacters(in: .whitespaces) : nil

        let publicKey: NIOSSHPublicKey
        do {
            publicKey = try NIOSSHPublicKey(openSSHPublicKey: line)
        } catch {
            throw SSHCertificateError.malformed(
                "The base64 body is not a well-formed \(type) certificate."
            )
        }

        guard let certified = NIOSSHCertifiedPublicKey(publicKey) else {
            throw SSHCertificateError.malformed("It parsed as a plain key rather than a certificate.")
        }

        return SSHCertificate(
            line: line,
            comment: comment?.isEmpty == true ? nil : comment,
            kind: Kind(certified.type),
            keyID: certified.keyID,
            serial: certified.serial,
            principals: certified.validPrincipals,
            // OpenSSH writes 0 for "valid from the beginning of time" and
            // UInt64.max for "-V always:forever"; neither is a date worth
            // showing anyone.
            validAfter: certified.validAfter == 0 ? nil : Date(timeIntervalSince1970: TimeInterval(certified.validAfter)),
            validBefore: certified.validBefore == .max
                ? nil : Date(timeIntervalSince1970: TimeInterval(certified.validBefore)),
            extensions: certified.extensions.keys.sorted(),
            criticalOptions: certified.criticalOptions,
            authorityFingerprint: SSHFingerprint.sha256(publicKeyLine: String(openSSHPublicKey: certified.signatureKey)),
            certifiedKeyFingerprint: SSHFingerprint.sha256(publicKeyLine: String(openSSHPublicKey: certified.key)),
            certifiedKey: certified
        )
    }

    /// Whether this certificate certifies the key in `publicKeyLine`.
    ///
    /// Checked at import: a certificate stored against the wrong key produces a
    /// confusing authentication failure much later, at the far end of a network
    /// round trip, with the server's log as the only clue.
    func certifies(publicKeyLine: String) -> Bool {
        guard let theirs = SSHFingerprint.sha256(publicKeyLine: publicKeyLine),
            let ours = self.certifiedKeyFingerprint
        else {
            return false
        }
        return theirs == ours
    }

    /// Validates this certificate as a *user* certificate for `principal`.
    ///
    /// This is what a server does. The client has no reason to, beyond telling
    /// the user something useful before the round trip — a certificate that
    /// expired last week should say so here rather than in a rejection.
    var validityDescription: String {
        let now = Date()
        if let validAfter, validAfter > now {
            return "Not valid until \(Self.format(validAfter))"
        }
        if let validBefore {
            return validBefore <= now
                ? "Expired \(Self.format(validBefore))"
                : "Valid until \(Self.format(validBefore))"
        }
        return "Valid indefinitely"
    }

    var isCurrentlyValid: Bool {
        let now = Date()
        if let validAfter, validAfter > now { return false }
        if let validBefore, validBefore <= now { return false }
        return true
    }

    private static func format(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}

extension SSHCertificate.Kind {
    // `CertificateType` is a struct wrapping a UInt32 rather than an enum, so
    // this compares rather than switches.
    fileprivate init(_ type: NIOSSHCertifiedPublicKey.CertificateType) {
        if type == .user {
            self = .user
        } else if type == .host {
            self = .host
        } else {
            self = .unknown
        }
    }
}

// MARK: - Certificate authorities

/// The certificate authorities this client trusts to vouch for a *host*.
///
/// The equivalent of OpenSSH's `@cert-authority` lines in `known_hosts`. Entered
/// in Settings as public key lines, one per line, exactly as they appear in the
/// CA's `.pub` file.
struct SSHTrustedAuthorities: Sendable {
    /// One entry per line of the setting, in order, so a bad line can be
    /// reported next to the good ones rather than silently dropped.
    struct Entry: Sendable, Identifiable {
        let id: Int
        let text: String
        let key: NIOSSHPublicKey?
        let fingerprint: String?
        let comment: String?

        var isValid: Bool { self.key != nil }
    }

    let entries: [Entry]

    var keys: [NIOSSHPublicKey] { self.entries.compactMap(\.key) }
    var isEmpty: Bool { self.keys.isEmpty }

    /// Parses the raw text of the Settings field.
    init(text: String) {
        var entries: [Entry] = []
        for (index, rawLine) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            // Blank lines and comments are how people annotate a list of keys.
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }

            let fields = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            let keyText = fields.count >= 2 ? "\(fields[0]) \(fields[1])" : line
            let comment = fields.count > 2 ? String(fields[2]) : nil

            let key = try? NIOSSHPublicKey(openSSHPublicKey: keyText)
            entries.append(
                Entry(
                    id: index,
                    text: line,
                    key: key,
                    fingerprint: key.flatMap { _ in SSHFingerprint.sha256(publicKeyLine: keyText) },
                    comment: comment
                )
            )
        }
        self.entries = entries
    }
}
