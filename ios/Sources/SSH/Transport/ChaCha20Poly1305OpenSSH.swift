import Foundation

/// The `chacha20-poly1305@openssh.com` packet construction.
///
/// OpenSSH's cipher is *not* the RFC 8439 AEAD that `CryptoKit.ChaChaPoly`
/// implements, and the differences are structural rather than cosmetic:
///
/// * The 64-byte key is split in two. `K_main` (the first 32 bytes) encrypts
///   the payload; `K_header` (the last 32) encrypts the 4-byte packet length,
///   so a passive observer cannot see packet boundaries.
/// * The nonce is the packet sequence number as a big-endian 64-bit integer, in
///   the original djb framing (8-byte nonce, 64-bit block counter) rather than
///   RFC 8439's 96-bit nonce and 32-bit counter.
/// * The Poly1305 one-time key is block 0 of `K_main`'s keystream; the payload
///   is encrypted starting at block 1.
/// * The tag covers `encrypted_length || encrypted_payload` **raw** — no
///   `pad16`, no length trailer. That alone rules out reusing `ChaChaPoly`.
///
/// ## Where this is used
///
/// ``ChaCha20Poly1305TransportProtection`` wraps it as a
/// `NIOSSHTransportProtection`, which is what NIOSSH negotiates and drives.
/// Keeping the construction separate from the adapter is what lets the tests
/// here pin it to the RFC 8439 vectors without a handshake in the way.
///
/// It took a forked swift-nio-ssh (#008D0) to make that wrapping possible at
/// all. Two independent blockers, both in the library:
///
/// 1. **The length nonce was unavailable at the only moment it was needed.**
///    `decryptFirstBlock` must leave the packet length in plaintext, and it was
///    handed no sequence number — but the sequence number *is* the nonce the
///    length was encrypted under. It now takes one.
/// 2. **The 64-byte key could not be derived.** The library generated session
///    keys by truncating a *single* key-exchange hash rather than running
///    RFC 4253 §7.2's expansion loop, so the most key material it could produce
///    was the exchange hash's length: 32 bytes for `curve25519-sha256`. The
///    fork expands.
enum ChaCha20Poly1305OpenSSH {
    static let keySize = 64
    static let tagSize = Poly1305.tagSize
    static let lengthFieldSize = 4

    enum Failure: Error, Equatable {
        case badKeySize(Int)
        case packetTooShort(Int)
        case tagMismatch
    }

    /// Encrypt one SSH packet.
    ///
    /// - Parameters:
    ///   - packet: `length || padding_length || payload || padding`, plaintext.
    ///   - key: the 64-byte session key, `K_main || K_header`.
    ///   - sequenceNumber: the packet's SSH sequence number.
    /// - Returns: `encrypted_length || encrypted_body || tag`.
    static func seal(
        packet: [UInt8],
        key: [UInt8],
        sequenceNumber: UInt32
    ) throws -> [UInt8] {
        guard key.count == Self.keySize else { throw Failure.badKeySize(key.count) }
        guard packet.count > Self.lengthFieldSize else {
            throw Failure.packetTooShort(packet.count)
        }

        let mainKey = Array(key[0..<32])
        let headerKey = Array(key[32..<64])
        let nonce = Self.nonce(for: sequenceNumber)

        var lengthField = Array(packet[0..<Self.lengthFieldSize])
        ChaCha20.applyOpenSSH(to: &lengthField, key: headerKey, nonce: nonce, initialCounter: 0)

        var body = Array(packet[Self.lengthFieldSize...])
        ChaCha20.applyOpenSSH(to: &body, key: mainKey, nonce: nonce, initialCounter: 1)

        let ciphertext = lengthField + body
        return ciphertext + Poly1305.authenticate(ciphertext, key: Self.polyKey(mainKey, nonce))
    }

    /// Decrypt the 4-byte length field alone, which is what an SSH parser needs
    /// before it knows how many more bytes to wait for.
    static func decryptLength(
        _ encryptedLength: [UInt8],
        key: [UInt8],
        sequenceNumber: UInt32
    ) throws -> UInt32 {
        guard key.count == Self.keySize else { throw Failure.badKeySize(key.count) }
        guard encryptedLength.count == Self.lengthFieldSize else {
            throw Failure.packetTooShort(encryptedLength.count)
        }
        var field = encryptedLength
        ChaCha20.applyOpenSSH(
            to: &field,
            key: Array(key[32..<64]),
            nonce: Self.nonce(for: sequenceNumber),
            initialCounter: 0
        )
        return (UInt32(field[0]) << 24) | (UInt32(field[1]) << 16) | (UInt32(field[2]) << 8)
            | UInt32(field[3])
    }

    /// Verify and decrypt one sealed packet, returning the plaintext packet
    /// (`length || padding_length || payload || padding`).
    static func open(
        sealed: [UInt8],
        key: [UInt8],
        sequenceNumber: UInt32
    ) throws -> [UInt8] {
        guard key.count == Self.keySize else { throw Failure.badKeySize(key.count) }
        guard sealed.count > Self.lengthFieldSize + Self.tagSize else {
            throw Failure.packetTooShort(sealed.count)
        }

        let mainKey = Array(key[0..<32])
        let headerKey = Array(key[32..<64])
        let nonce = Self.nonce(for: sequenceNumber)

        let ciphertext = Array(sealed[0..<(sealed.count - Self.tagSize)])
        let tag = Array(sealed[(sealed.count - Self.tagSize)...])

        // Authenticate before decrypting: the whole point of the construction.
        let expected = Poly1305.authenticate(ciphertext, key: Self.polyKey(mainKey, nonce))
        guard Poly1305.constantTimeEquals(expected, tag) else { throw Failure.tagMismatch }

        var lengthField = Array(ciphertext[0..<Self.lengthFieldSize])
        ChaCha20.applyOpenSSH(to: &lengthField, key: headerKey, nonce: nonce, initialCounter: 0)

        var body = Array(ciphertext[Self.lengthFieldSize...])
        ChaCha20.applyOpenSSH(to: &body, key: mainKey, nonce: nonce, initialCounter: 1)

        return lengthField + body
    }

    // MARK: - Helpers

    /// The Poly1305 one-time key: the first 32 bytes of `K_main`'s keystream
    /// for this packet (block 0), which is why the payload starts at block 1.
    private static func polyKey(_ mainKey: [UInt8], _ nonce: [UInt8]) -> [UInt8] {
        var key = [UInt8](repeating: 0, count: Poly1305.keySize)
        ChaCha20.applyOpenSSH(to: &key, key: mainKey, nonce: nonce, initialCounter: 0)
        return key
    }

    /// The 8-byte nonce: the sequence number, big-endian. SSH's counter is
    /// 32-bit and wraps; OpenSSH widens it to 64 bits, so the top four bytes
    /// are always zero.
    static func nonce(for sequenceNumber: UInt32) -> [UInt8] {
        withUnsafeBytes(of: UInt64(sequenceNumber).bigEndian) { Array($0) }
    }
}
