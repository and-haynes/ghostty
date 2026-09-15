import Foundation

/// ChaCha20, the stream cipher from RFC 8439 (and, in its original djb form,
/// from `chacha20-poly1305@openssh.com`).
///
/// CryptoKit exposes ChaCha20 only through the `ChaChaPoly` AEAD, whose framing
/// is RFC 8439's — 96-bit nonce, 32-bit counter, and a Poly1305 tag taken over
/// padded associated data with a length trailer. OpenSSH's SSH transport cipher
/// uses the *other* framing: two independently keyed ChaCha20 instances, a
/// 64-bit nonce, a 64-bit counter, and a tag over the raw bytes. None of that is
/// reachable through `ChaChaPoly`, so the core has to live here.
///
/// The block function below is the one primitive both framings share. It takes
/// words 12…15 of the state directly, which is precisely where the two
/// framings differ:
///
/// ```text
/// RFC 8439:  [12] = counter (u32)        [13…15] = nonce (12 bytes)
/// OpenSSH:   [12…13] = counter (u64 LE)  [14…15] = nonce (8 bytes)
/// ```
enum ChaCha20 {
    static let blockSize = 64
    static let keySize = 32

    /// "expand 32-byte k" — the ChaCha constants, as four little-endian words.
    private static let constants: (UInt32, UInt32, UInt32, UInt32) = (
        0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574
    )

    /// One 64-byte ChaCha20 block.
    ///
    /// - Parameters:
    ///   - key: 32 bytes. Anything else is a programming error, so it traps.
    ///   - words: state words 12, 13, 14 and 15, already in host order.
    static func block(key: [UInt8], words: (UInt32, UInt32, UInt32, UInt32)) -> [UInt8] {
        precondition(key.count == Self.keySize, "ChaCha20 needs a 32-byte key")

        var state = [UInt32](repeating: 0, count: 16)
        state[0] = Self.constants.0
        state[1] = Self.constants.1
        state[2] = Self.constants.2
        state[3] = Self.constants.3
        for index in 0..<8 {
            state[4 + index] = Self.loadLittleEndian(key, at: index * 4)
        }
        state[12] = words.0
        state[13] = words.1
        state[14] = words.2
        state[15] = words.3

        var working = state
        // 20 rounds = 10 iterations of (column round, diagonal round).
        for _ in 0..<10 {
            Self.quarterRound(&working, 0, 4, 8, 12)
            Self.quarterRound(&working, 1, 5, 9, 13)
            Self.quarterRound(&working, 2, 6, 10, 14)
            Self.quarterRound(&working, 3, 7, 11, 15)
            Self.quarterRound(&working, 0, 5, 10, 15)
            Self.quarterRound(&working, 1, 6, 11, 12)
            Self.quarterRound(&working, 2, 7, 8, 13)
            Self.quarterRound(&working, 3, 4, 9, 14)
        }

        var out = [UInt8](repeating: 0, count: Self.blockSize)
        for index in 0..<16 {
            let value = working[index] &+ state[index]
            out[index * 4] = UInt8(truncatingIfNeeded: value)
            out[index * 4 + 1] = UInt8(truncatingIfNeeded: value >> 8)
            out[index * 4 + 2] = UInt8(truncatingIfNeeded: value >> 16)
            out[index * 4 + 3] = UInt8(truncatingIfNeeded: value >> 24)
        }
        return out
    }

    // MARK: - RFC 8439 framing

    /// XOR `bytes` with the RFC 8439 keystream for `nonce` (12 bytes) starting
    /// at block number `counter`. Encryption and decryption are the same call.
    static func apply(
        to bytes: inout [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        initialCounter: UInt32
    ) {
        precondition(nonce.count == 12, "RFC 8439 ChaCha20 needs a 12-byte nonce")
        let nonceWords = (
            Self.loadLittleEndian(nonce, at: 0),
            Self.loadLittleEndian(nonce, at: 4),
            Self.loadLittleEndian(nonce, at: 8)
        )
        var counter = initialCounter
        var offset = 0
        while offset < bytes.count {
            let keystream = Self.block(
                key: key,
                words: (counter, nonceWords.0, nonceWords.1, nonceWords.2)
            )
            let span = min(Self.blockSize, bytes.count - offset)
            for index in 0..<span {
                bytes[offset + index] ^= keystream[index]
            }
            offset += span
            counter &+= 1
        }
    }

    // MARK: - OpenSSH framing

    /// XOR `bytes` with the keystream of the original (djb) ChaCha20 framing:
    /// an 8-byte nonce and a 64-bit little-endian block counter. This is what
    /// `chacha20-poly1305@openssh.com` uses.
    static func applyOpenSSH(
        to bytes: inout [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        initialCounter: UInt64
    ) {
        precondition(nonce.count == 8, "OpenSSH ChaCha20 uses an 8-byte nonce")
        let nonceWords = (
            Self.loadLittleEndian(nonce, at: 0),
            Self.loadLittleEndian(nonce, at: 4)
        )
        var counter = initialCounter
        var offset = 0
        while offset < bytes.count {
            let keystream = Self.block(
                key: key,
                words: (
                    UInt32(truncatingIfNeeded: counter),
                    UInt32(truncatingIfNeeded: counter >> 32),
                    nonceWords.0,
                    nonceWords.1
                )
            )
            let span = min(Self.blockSize, bytes.count - offset)
            for index in 0..<span {
                bytes[offset + index] ^= keystream[index]
            }
            offset += span
            counter &+= 1
        }
    }

    // MARK: - Helpers

    private static func quarterRound(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        s[a] = s[a] &+ s[b]
        s[d] = Self.rotateLeft(s[d] ^ s[a], 16)
        s[c] = s[c] &+ s[d]
        s[b] = Self.rotateLeft(s[b] ^ s[c], 12)
        s[a] = s[a] &+ s[b]
        s[d] = Self.rotateLeft(s[d] ^ s[a], 8)
        s[c] = s[c] &+ s[d]
        s[b] = Self.rotateLeft(s[b] ^ s[c], 7)
    }

    private static func rotateLeft(_ value: UInt32, _ amount: UInt32) -> UInt32 {
        (value << amount) | (value >> (32 - amount))
    }

    private static func loadLittleEndian(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }
}
