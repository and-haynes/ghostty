import Foundation

/// Poly1305, the one-time authenticator from RFC 8439 §2.5.
///
/// CryptoKit only exposes Poly1305 welded to ChaCha20 inside the `ChaChaPoly`
/// AEAD, and that AEAD authenticates `pad16(aad) || pad16(ciphertext) ||
/// len(aad) || len(ciphertext)`. `chacha20-poly1305@openssh.com` authenticates
/// the packet bytes *raw*, with no padding and no length trailer, so the AEAD
/// cannot be borrowed and the authenticator has to exist on its own.
///
/// This is a port of the public-domain `poly1305-donna` 32-bit reference:
/// the accumulator is five 26-bit limbs, which keeps every intermediate
/// product inside a `UInt64`. It is not constant-time against a
/// cache-timing attacker in the way an assembly implementation is; it *is*
/// free of secret-dependent branches and secret-dependent memory indices,
/// which is the property that matters here.
struct Poly1305 {
    static let tagSize = 16
    static let keySize = 32
    private static let blockSize = 16

    private var r = [UInt64](repeating: 0, count: 5)
    private var h = [UInt64](repeating: 0, count: 5)
    private var pad = [UInt64](repeating: 0, count: 4)
    private var buffer = [UInt8](repeating: 0, count: Poly1305.blockSize)
    private var leftover = 0
    private var finished = false

    /// - Parameter key: the 32-byte one-time key: `r` (clamped) then `s`.
    init(key: [UInt8]) {
        precondition(key.count == Self.keySize, "Poly1305 needs a 32-byte one-time key")

        // r is clamped, per RFC 8439 §2.5: the top four bits of bytes 3, 7, 11
        // and 15 are cleared, as are the bottom two bits of bytes 4, 8 and 12.
        // Splitting into 26-bit limbs and masking does both at once.
        self.r[0] = UInt64(Self.load32(key, 0)) & 0x3FF_FFFF
        self.r[1] = UInt64(Self.load32(key, 3) >> 2) & 0x3FF_FF03
        self.r[2] = UInt64(Self.load32(key, 6) >> 4) & 0x3FF_C0FF
        self.r[3] = UInt64(Self.load32(key, 9) >> 6) & 0x3F0_3FFF
        self.r[4] = UInt64(Self.load32(key, 12) >> 8) & 0x00F_FFFF

        self.pad[0] = UInt64(Self.load32(key, 16))
        self.pad[1] = UInt64(Self.load32(key, 20))
        self.pad[2] = UInt64(Self.load32(key, 24))
        self.pad[3] = UInt64(Self.load32(key, 28))
    }

    mutating func update<Bytes: Collection>(_ message: Bytes) where Bytes.Element == UInt8 {
        var input = [UInt8](message)
        var offset = 0

        // Top up a partial block held over from the previous call.
        if self.leftover > 0 {
            let want = min(Self.blockSize - self.leftover, input.count)
            for index in 0..<want {
                self.buffer[self.leftover + index] = input[index]
            }
            self.leftover += want
            offset += want
            guard self.leftover == Self.blockSize else { return }
            // Copied out first: passing `self.buffer` straight into a mutating
            // method would be two overlapping accesses to `self`.
            let held = self.buffer
            self.blocks(held, from: 0, count: Self.blockSize, isFinal: false)
            self.leftover = 0
        }

        let whole = ((input.count - offset) / Self.blockSize) * Self.blockSize
        if whole > 0 {
            self.blocks(input, from: offset, count: whole, isFinal: false)
            offset += whole
        }

        if offset < input.count {
            let rest = input.count - offset
            for index in 0..<rest {
                self.buffer[index] = input[offset + index]
            }
            self.leftover = rest
        }

        // Don't leave a copy of the message on the heap longer than needed.
        input.removeAll(keepingCapacity: false)
    }

    mutating func finalize() -> [UInt8] {
        precondition(!self.finished, "Poly1305 finalized twice")
        self.finished = true

        if self.leftover > 0 {
            self.buffer[self.leftover] = 1
            for index in (self.leftover + 1)..<Self.blockSize {
                self.buffer[index] = 0
            }
            let held = self.buffer
            self.blocks(held, from: 0, count: Self.blockSize, isFinal: true)
        }

        // Carry the accumulator fully.
        var h0 = self.h[0], h1 = self.h[1], h2 = self.h[2], h3 = self.h[3], h4 = self.h[4]
        var c = h1 >> 26
        h1 &= 0x3FF_FFFF
        h2 &+= c
        c = h2 >> 26
        h2 &= 0x3FF_FFFF
        h3 &+= c
        c = h3 >> 26
        h3 &= 0x3FF_FFFF
        h4 &+= c
        c = h4 >> 26
        h4 &= 0x3FF_FFFF
        h0 &+= c &* 5
        c = h0 >> 26
        h0 &= 0x3FF_FFFF
        h1 &+= c

        // g = h + 5. If that does not overflow 2^130 then h was already < p and
        // we keep h; otherwise g is h mod p. The choice is made with a mask so
        // it does not become a secret-dependent branch.
        var g0 = h0 &+ 5
        c = g0 >> 26
        g0 &= 0x3FF_FFFF
        var g1 = h1 &+ c
        c = g1 >> 26
        g1 &= 0x3FF_FFFF
        var g2 = h2 &+ c
        c = g2 >> 26
        g2 &= 0x3FF_FFFF
        var g3 = h3 &+ c
        c = g3 >> 26
        g3 &= 0x3FF_FFFF
        var g4 = (h4 &+ c) &- (UInt64(1) << 26)

        var mask = (g4 >> 63) &- 1
        g0 &= mask
        g1 &= mask
        g2 &= mask
        g3 &= mask
        g4 &= mask
        mask = ~mask
        h0 = (h0 & mask) | g0
        h1 = (h1 & mask) | g1
        h2 = (h2 & mask) | g2
        h3 = (h3 & mask) | g3
        h4 = (h4 & mask) | g4

        // Repack the five 26-bit limbs as four 32-bit words (h mod 2^128).
        h0 = ((h0) | (h1 << 26)) & 0xFFFF_FFFF
        h1 = ((h1 >> 6) | (h2 << 20)) & 0xFFFF_FFFF
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xFFFF_FFFF
        h3 = ((h3 >> 18) | (h4 << 8)) & 0xFFFF_FFFF

        // tag = (h + s) mod 2^128
        var f = h0 &+ self.pad[0]
        h0 = f & 0xFFFF_FFFF
        f = h1 &+ self.pad[1] &+ (f >> 32)
        h1 = f & 0xFFFF_FFFF
        f = h2 &+ self.pad[2] &+ (f >> 32)
        h2 = f & 0xFFFF_FFFF
        f = h3 &+ self.pad[3] &+ (f >> 32)
        h3 = f & 0xFFFF_FFFF

        var tag = [UInt8](repeating: 0, count: Self.tagSize)
        Self.store32(&tag, 0, UInt32(truncatingIfNeeded: h0))
        Self.store32(&tag, 4, UInt32(truncatingIfNeeded: h1))
        Self.store32(&tag, 8, UInt32(truncatingIfNeeded: h2))
        Self.store32(&tag, 12, UInt32(truncatingIfNeeded: h3))
        return tag
    }

    /// One-shot convenience.
    static func authenticate<Bytes: Collection>(
        _ message: Bytes,
        key: [UInt8]
    ) -> [UInt8] where Bytes.Element == UInt8 {
        var mac = Poly1305(key: key)
        mac.update(message)
        return mac.finalize()
    }

    /// Constant-time tag comparison. Never compare MACs with `==` on arrays.
    static func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in 0..<lhs.count {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }

    // MARK: - Core

    private mutating func blocks(_ input: [UInt8], from start: Int, count: Int, isFinal: Bool) {
        // The implicit high bit that terminates every full block. The final,
        // short block supplies its own 0x01 byte instead (see `finalize`).
        let hibit: UInt64 = isFinal ? 0 : (UInt64(1) << 24)

        let r0 = self.r[0], r1 = self.r[1], r2 = self.r[2], r3 = self.r[3], r4 = self.r[4]
        let s1 = r1 &* 5, s2 = r2 &* 5, s3 = r3 &* 5, s4 = r4 &* 5

        var h0 = self.h[0], h1 = self.h[1], h2 = self.h[2], h3 = self.h[3], h4 = self.h[4]

        var offset = start
        let end = start + count
        while offset < end {
            // h += next block, read as a little-endian 128-bit number plus the
            // implicit 2^128 bit.
            h0 &+= UInt64(Self.load32(input, offset)) & 0x3FF_FFFF
            h1 &+= UInt64(Self.load32(input, offset + 3) >> 2) & 0x3FF_FFFF
            h2 &+= UInt64(Self.load32(input, offset + 6) >> 4) & 0x3FF_FFFF
            h3 &+= UInt64(Self.load32(input, offset + 9) >> 6) & 0x3FF_FFFF
            h4 &+= UInt64(Self.load32(input, offset + 12) >> 8) | hibit

            // h *= r, folded mod 2^130 - 5 (hence the ×5 on the wrapped limbs).
            let d0 = h0 &* r0 &+ h1 &* s4 &+ h2 &* s3 &+ h3 &* s2 &+ h4 &* s1
            let d1 = h0 &* r1 &+ h1 &* r0 &+ h2 &* s4 &+ h3 &* s3 &+ h4 &* s2
            let d2 = h0 &* r2 &+ h1 &* r1 &+ h2 &* r0 &+ h3 &* s4 &+ h4 &* s3
            let d3 = h0 &* r3 &+ h1 &* r2 &+ h2 &* r1 &+ h3 &* r0 &+ h4 &* s4
            let d4 = h0 &* r4 &+ h1 &* r3 &+ h2 &* r2 &+ h3 &* r1 &+ h4 &* r0

            var carry = d0 >> 26
            h0 = d0 & 0x3FF_FFFF
            let e1 = d1 &+ carry
            carry = e1 >> 26
            h1 = e1 & 0x3FF_FFFF
            let e2 = d2 &+ carry
            carry = e2 >> 26
            h2 = e2 & 0x3FF_FFFF
            let e3 = d3 &+ carry
            carry = e3 >> 26
            h3 = e3 & 0x3FF_FFFF
            let e4 = d4 &+ carry
            carry = e4 >> 26
            h4 = e4 & 0x3FF_FFFF
            h0 &+= carry &* 5
            carry = h0 >> 26
            h0 &= 0x3FF_FFFF
            h1 &+= carry

            offset += Self.blockSize
        }

        self.h[0] = h0
        self.h[1] = h1
        self.h[2] = h2
        self.h[3] = h3
        self.h[4] = h4
    }

    private static func load32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private static func store32(_ bytes: inout [UInt8], _ offset: Int, _ value: UInt32) {
        bytes[offset] = UInt8(truncatingIfNeeded: value)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 8)
        bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 16)
        bytes[offset + 3] = UInt8(truncatingIfNeeded: value >> 24)
    }
}
