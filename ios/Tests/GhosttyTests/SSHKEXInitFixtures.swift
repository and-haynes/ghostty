import XCTest

@testable import Ghostty

/// Recorded server algorithm lists, so the mismatch explainer is tested against
/// what a real server actually says rather than a hand-written approximation.
enum SSHKEXInitFixtures {
    /// pi-a (10.0.0.41), OpenSSH 10.3, captured 2026-09-15. The raw
    /// `SSH_MSG_KEXINIT` packet exactly as it came off the wire, length prefix
    /// and padding included.
    static let openSSH103Packet: [UInt8] = bytes(
        from: """
            0000042c081469bbb85e42f321ddee00659d0f8ab155000000df6d6c6b656d37
            36387832353531392d7368613235362c736e747275703736317832353531392d
            7368613531322c736e747275703736317832353531392d736861353132406f70
            656e7373682e636f6d2c637572766532353531392d7368613235362c63757276
            6532353531392d736861323536406c69627373682e6f72672c656364682d7368
            61322d6e697374703235362c656364682d736861322d6e697374703338342c65
            6364682d736861322d6e697374703532312c6578742d696e666f2d732c6b6578
            2d7374726963742d732d763030406f70656e7373682e636f6d0000005a727361
            2d736861322d3531322c7273612d736861322d3235362c65636473612d736861
            322d6e697374703235362c7373682d656432353531392c7373682d6564323535
            31392d636572742d763031406f70656e7373682e636f6d0000006c6368616368
            6132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d
            67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e73
            73682e636f6d2c6165733132382d6374722c6165733139322d6374722c616573
            3235362d6374720000006c63686163686132302d706f6c7931333035406f7065
            6e7373682e636f6d2c6165733132382d67636d406f70656e7373682e636f6d2c
            6165733235362d67636d406f70656e7373682e636f6d2c6165733132382d6374
            722c6165733139322d6374722c6165733235362d637472000000d5756d61632d
            36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d40
            6f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70
            656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e
            7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f
            6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f
            70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d7368
            61322d3531322c686d61632d73686131000000d5756d61632d36342d65746d40
            6f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e737368
            2e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e63
            6f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d
            2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d
            3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e
            636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c
            686d61632d73686131000000156e6f6e652c7a6c6962406f70656e7373682e63
            6f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d0000000000
            00000000000000000000000000000000
            """
    )

    /// A server with RSA host keys, CTR ciphers and no AEAD — the shape of the
    /// appliance in #008A0 that this app could not reach at all. Synthetic, but
    /// assembled by the same encoder an SSH server uses, so it exercises the
    /// parser identically.
    static let rsaAndCTROnlyPacket: [UInt8] = makePacket(
        keyExchange: ["curve25519-sha256", "diffie-hellman-group14-sha256"],
        hostKeys: ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"],
        ciphers: ["aes128-ctr", "aes192-ctr", "aes256-ctr"],
        macs: ["hmac-sha1", "hmac-sha2-256"]
    )

    /// Dropbear's usual shape: no GCM, no RSA-only problem, but nothing
    /// swift-nio-ssh ships a cipher for.
    static let ctrOnlyPacket: [UInt8] = makePacket(
        keyExchange: ["curve25519-sha256", "ecdh-sha2-nistp256"],
        hostKeys: ["ssh-ed25519"],
        ciphers: ["aes128-ctr", "aes256-ctr"],
        macs: ["hmac-sha1", "hmac-sha2-256"]
    )

    /// A hardened configuration: chacha20 only, and a key exchange that cannot
    /// produce the 64 bytes chacha20 needs.
    static let chachaOnlyPacket: [UInt8] = makePacket(
        keyExchange: ["curve25519-sha256"],
        hostKeys: ["ssh-ed25519"],
        ciphers: ["chacha20-poly1305@openssh.com"],
        macs: ["hmac-sha2-512-etm@openssh.com"]
    )

    // MARK: - Building

    /// Hex to bytes, ignoring the whitespace a readable literal needs.
    static func bytes(from hex: String) -> [UInt8] {
        let digits = Array(hex.filter { !$0.isWhitespace })
        var out: [UInt8] = []
        out.reserveCapacity(digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            out.append(UInt8(String(digits[index...(index + 1)]), radix: 16)!)
        }
        return out
    }

    /// Encode a `SSH_MSG_KEXINIT` the way a server would: length, padding
    /// length, message type, a 16-byte cookie, ten name-lists, a boolean and a
    /// reserved word (RFC 4253 §7.1).
    static func makePacket(
        keyExchange: [String],
        hostKeys: [String],
        ciphers: [String],
        macs: [String],
        compression: [String] = ["none"]
    ) -> [UInt8] {
        var payload: [UInt8] = [20]
        payload.append(contentsOf: [UInt8](repeating: 0x5A, count: 16))
        let lists = [
            keyExchange, hostKeys, ciphers, ciphers, macs, macs,
            compression, compression, [], [],
        ]
        for list in lists {
            let text = Array(list.joined(separator: ",").utf8)
            payload.append(contentsOf: Self.uint32(UInt32(text.count)))
            payload.append(contentsOf: text)
        }
        payload.append(0)  // first_kex_packet_follows
        payload.append(contentsOf: Self.uint32(0))  // reserved

        // Padding to an 8-byte boundary, at least four bytes, exactly as the
        // cleartext phase of the protocol requires.
        var paddingLength = 8 - ((payload.count + 5) % 8)
        if paddingLength < 4 { paddingLength += 8 }
        let packetLength = payload.count + paddingLength + 1

        var packet = Self.uint32(UInt32(packetLength))
        packet.append(UInt8(paddingLength))
        packet.append(contentsOf: payload)
        packet.append(contentsOf: [UInt8](repeating: 0, count: paddingLength))
        return packet
    }

    private static func uint32(_ value: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ]
    }
}
