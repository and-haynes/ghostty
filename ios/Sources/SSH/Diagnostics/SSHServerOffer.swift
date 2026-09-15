import Foundation

/// What a server says it can do, read straight off the wire.
///
/// An SSH server announces its whole algorithm menu in the clear, in the first
/// packet after the identification string, before anything is authenticated or
/// even negotiated. Reading it costs one TCP connection and tells us exactly
/// why a handshake failed — which beats `NIOSSHError.keyExchangeNegotiationFailure`,
/// a sentence that tells a person nothing and an engineer only slightly more.
struct SSHServerOffer: Equatable, Sendable {
    /// The server's identification string, e.g. `SSH-2.0-OpenSSH_10.3`.
    /// Any preamble lines before it are kept separately.
    var banner: String
    /// Lines the server sent before its identification string. Rare, but this
    /// is where a TCP-wrappers refusal or a legal notice arrives.
    var preamble: [String]

    var keyExchangeAlgorithms: [String]
    var hostKeyAlgorithms: [String]
    var ciphersClientToServer: [String]
    var ciphersServerToClient: [String]
    var macsClientToServer: [String]
    var macsServerToClient: [String]
    var compressionClientToServer: [String]
    var compressionServerToClient: [String]

    /// The software name from the identification string, e.g. `OpenSSH_10.3`.
    var softwareVersion: String? {
        let fields = banner.split(separator: "-", maxSplits: 2, omittingEmptySubsequences: false)
        guard fields.count >= 3 else { return nil }
        return String(fields[2]).split(separator: " ").first.map(String.init)
    }

    /// Ciphers offered in *both* directions. swift-nio-ssh only accepts a
    /// symmetric negotiation, so this is the set that can actually be chosen.
    var ciphers: [String] {
        let reverse = Set(ciphersServerToClient)
        return ciphersClientToServer.filter { reverse.contains($0) }
    }

    var macs: [String] {
        let reverse = Set(macsServerToClient)
        return macsClientToServer.filter { reverse.contains($0) }
    }
}

// MARK: - Parsing

/// Reads the `SSH_MSG_KEXINIT` packet that opens every SSH connection.
///
/// The packet is plaintext at this stage of the protocol, so this is a plain
/// binary parse with no crypto: a 4-byte length, a padding-length byte, the
/// payload, and padding. The payload is a message type, a 16-byte cookie, ten
/// comma-separated name-lists, a boolean and a reserved word (RFC 4253 §7.1).
///
/// Every read is bounds-checked and returns an error rather than trapping: this
/// parses bytes from a machine that has not authenticated itself to us.
enum SSHKEXInitParser {
    static let messageType: UInt8 = 20

    enum Failure: Error, Equatable, LocalizedError {
        case truncated
        case notKEXInit(UInt8)
        case oversizedPacket(UInt32)

        var errorDescription: String? {
            switch self {
            case .truncated:
                return "The server's algorithm list arrived incomplete."
            case .notKEXInit(let type):
                return """
                    The server's first message was type \(type), not the algorithm \
                    list every SSH server is required to send first. It may not be \
                    an SSH server.
                    """
            case .oversizedPacket(let length):
                return "The server announced a \(length)-byte first packet, which is not plausible."
            }
        }
    }

    /// A sane bound for a KEXINIT. OpenSSH's is a few hundred bytes; anything
    /// past this is a length-prefix attack rather than an algorithm list.
    private static let maximumPacketLength: UInt32 = 64 * 1024

    /// Parse the packet, given the bytes that follow the identification string.
    ///
    /// - Returns: the ten name-lists, or nil if `bytes` does not yet hold a
    ///   whole packet (the caller should read more).
    static func parse(packet bytes: [UInt8]) throws -> [[String]]? {
        guard bytes.count >= 5 else { return nil }
        let packetLength =
            (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16) | (UInt32(bytes[2]) << 8)
            | UInt32(bytes[3])
        guard packetLength <= Self.maximumPacketLength, packetLength >= 2 else {
            throw Failure.oversizedPacket(packetLength)
        }
        guard bytes.count >= Int(packetLength) + 4 else { return nil }

        let paddingLength = Int(bytes[4])
        let payloadStart = 5
        let payloadEnd = 4 + Int(packetLength) - paddingLength
        guard payloadEnd > payloadStart else { throw Failure.truncated }

        let payload = Array(bytes[payloadStart..<payloadEnd])
        guard let type = payload.first else { throw Failure.truncated }
        guard type == Self.messageType else { throw Failure.notKEXInit(type) }

        // message type (1) + cookie (16)
        var offset = 17
        var lists: [[String]] = []
        for _ in 0..<10 {
            guard offset + 4 <= payload.count else { throw Failure.truncated }
            let length =
                (Int(payload[offset]) << 24) | (Int(payload[offset + 1]) << 16)
                | (Int(payload[offset + 2]) << 8) | Int(payload[offset + 3])
            offset += 4
            guard length >= 0, offset + length <= payload.count else { throw Failure.truncated }
            let text = String(decoding: payload[offset..<(offset + length)], as: UTF8.self)
            offset += length
            lists.append(
                text.split(separator: ",").map(String.init).filter { !$0.isEmpty }
            )
        }
        return lists
    }

    /// Assemble an offer from a banner and a parsed KEXINIT.
    static func offer(banner: String, preamble: [String], lists: [[String]]) -> SSHServerOffer {
        func list(_ index: Int) -> [String] { index < lists.count ? lists[index] : [] }
        return SSHServerOffer(
            banner: banner,
            preamble: preamble,
            keyExchangeAlgorithms: list(0),
            hostKeyAlgorithms: list(1),
            ciphersClientToServer: list(2),
            ciphersServerToClient: list(3),
            macsClientToServer: list(4),
            macsServerToClient: list(5),
            compressionClientToServer: list(6),
            compressionServerToClient: list(7)
        )
    }
}
