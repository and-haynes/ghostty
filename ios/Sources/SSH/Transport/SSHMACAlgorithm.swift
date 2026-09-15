import Crypto
import Foundation

/// The HMAC algorithms this app can negotiate for non-AEAD ciphers.
///
/// swift-nio-ssh ships only the two OpenSSH AES-GCM modes, which carry their
/// own tag and ignore MAC negotiation entirely. Pairing AES-CTR with an HMAC
/// means supplying the MAC half ourselves — CryptoKit has both hash functions,
/// so this is a thin, well-tested wrapper rather than an implementation.
enum SSHMACAlgorithm: String, CaseIterable, Sendable {
    case hmacSHA256 = "hmac-sha2-256"
    case hmacSHA512 = "hmac-sha2-512"

    /// The wire name without OpenSSH's encrypt-then-MAC suffix.
    var plainName: String { self.rawValue }

    /// The wire name of the encrypt-then-MAC variant (RFC 4253's MAC-then-
    /// encrypt ordering is the historical mistake OpenSSH's `-etm` names fix).
    var etmName: String { self.rawValue + "-etm@openssh.com" }

    /// The MAC key length in bytes. Equal to the digest length, as RFC 6668
    /// specifies for both of these.
    var keyLength: Int {
        switch self {
        case .hmacSHA256: return 32
        case .hmacSHA512: return 64
        }
    }

    /// The tag length in bytes. Neither of these is truncated.
    var tagLength: Int { self.keyLength }

    /// HMAC over `sequenceNumber || bytes`, which is what RFC 4253 §6.4 means
    /// by "computed over the sequence number followed by the packet".
    func authenticate(
        sequenceNumber: UInt32,
        over regions: [Data],
        key: SymmetricKey
    ) -> [UInt8] {
        let sequence = Data(withUnsafeBytes(of: sequenceNumber.bigEndian) { Array($0) })
        switch self {
        case .hmacSHA256:
            var mac = Crypto.HMAC<SHA256>(key: key)
            mac.update(data: sequence)
            for region in regions { mac.update(data: region) }
            return Array(mac.finalize())
        case .hmacSHA512:
            var mac = Crypto.HMAC<SHA512>(key: key)
            mac.update(data: sequence)
            for region in regions { mac.update(data: region) }
            return Array(mac.finalize())
        }
    }

    /// Constant-time verification. A byte-by-byte `==` on a MAC is a timing
    /// oracle, and on this code path it is an oracle for forged packets.
    func verify(
        _ tag: [UInt8],
        sequenceNumber: UInt32,
        over regions: [Data],
        key: SymmetricKey
    ) -> Bool {
        let expected = self.authenticate(sequenceNumber: sequenceNumber, over: regions, key: key)
        guard expected.count == tag.count else { return false }
        var difference: UInt8 = 0
        for index in 0..<expected.count {
            difference |= expected[index] ^ tag[index]
        }
        return difference == 0
    }
}
