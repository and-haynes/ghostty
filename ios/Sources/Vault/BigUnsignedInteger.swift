import Foundation

/// The two big-integer operations importing an OpenSSH RSA key needs, and no
/// more.
///
/// OpenSSH's `openssh-key-v1` container stores an RSA private key as
/// `n, e, d, iqmp, p, q`. PKCS#1 — the only private-key encoding
/// `SecKeyCreateWithData` accepts — additionally wants the CRT exponents
/// `d mod (p-1)` and `d mod (q-1)`, so importing a key OpenSSH wrote means
/// computing two modular reductions of a 3072-bit number by a 1536-bit one.
/// There is no big-integer type in the standard library and none exposed by
/// CryptoKit, so here are the twenty lines that do it.
///
/// Deliberately *not* a general big-integer type and deliberately not
/// constant-time: it runs once, at import, on a key the user just handed us,
/// and it is followed immediately by `SecKeyCreateWithData` validating the
/// result. Anything it gets wrong fails loudly there rather than silently
/// producing a key that signs incorrectly.
enum BigUnsignedInteger {
    /// `value - 1`, for a big-endian magnitude. Used to turn `p` into `p - 1`.
    ///
    /// - Returns: nil if `value` is zero, which no prime is.
    static func decrement(_ value: Data) -> Data? {
        var bytes = [UInt8](value)
        var index = bytes.count - 1
        while index >= 0 {
            if bytes[index] > 0 {
                bytes[index] -= 1
                return Data(Self.trimmed(bytes))
            }
            bytes[index] = 0xFF
            index -= 1
        }
        return nil
    }

    /// `dividend mod divisor`, both big-endian magnitudes.
    ///
    /// Bitwise long division: shift one bit of the dividend into a remainder
    /// that is never wider than the divisor, and subtract when it fits. For a
    /// 4096-bit key that is 4096 iterations over a 257-byte remainder, which is
    /// imperceptible next to the Keychain write that follows it.
    static func modulo(_ dividend: Data, _ divisor: Data) -> Data? {
        let divisorBytes = Self.trimmed([UInt8](divisor))
        guard !divisorBytes.isEmpty, divisorBytes.contains(where: { $0 != 0 }) else { return nil }

        // One byte wider than the divisor: doubling a remainder that is only
        // just below the divisor needs the extra bit, and losing it silently
        // gives a plausible-looking wrong answer.
        var remainder = [UInt8](repeating: 0, count: divisorBytes.count + 1)
        for byte in dividend {
            for bit in (0..<8).reversed() {
                Self.shiftLeftOneBit(&remainder, carrying: (byte >> UInt8(bit)) & 1)
                if Self.compare(remainder, divisorBytes) >= 0 {
                    Self.subtract(&remainder, divisorBytes)
                }
            }
        }
        return Data(Self.trimmed(remainder))
    }

    // MARK: - Primitives

    /// Shift left by one bit, bringing in `carrying` at the bottom.
    ///
    /// Nothing falls off the top: the buffer is one byte wider than the
    /// divisor, and the caller subtracts immediately afterwards, so the value
    /// never grows past twice the divisor.
    private static func shiftLeftOneBit(_ value: inout [UInt8], carrying bit: UInt8) {
        var carry = bit
        var index = value.count - 1
        while index >= 0 {
            let next = value[index] >> 7
            value[index] = (value[index] << 1) | carry
            carry = next
            index -= 1
        }
    }

    /// -1, 0 or 1, comparing two equal-or-shorter big-endian magnitudes.
    private static func compare(_ lhs: [UInt8], _ rhs: [UInt8]) -> Int {
        let width = max(lhs.count, rhs.count)
        for index in 0..<width {
            let left = index < width - lhs.count ? 0 : lhs[index - (width - lhs.count)]
            let right = index < width - rhs.count ? 0 : rhs[index - (width - rhs.count)]
            if left != right { return left < right ? -1 : 1 }
        }
        return 0
    }

    /// `lhs -= rhs`, where `lhs >= rhs` and `lhs` is at least as wide.
    private static func subtract(_ lhs: inout [UInt8], _ rhs: [UInt8]) {
        var borrow = 0
        var leftIndex = lhs.count - 1
        var rightIndex = rhs.count - 1
        while leftIndex >= 0 {
            let right = rightIndex >= 0 ? Int(rhs[rightIndex]) : 0
            var difference = Int(lhs[leftIndex]) - right - borrow
            if difference < 0 {
                difference += 256
                borrow = 1
            } else {
                borrow = 0
            }
            lhs[leftIndex] = UInt8(difference)
            leftIndex -= 1
            rightIndex -= 1
        }
    }

    private static func trimmed(_ bytes: [UInt8]) -> [UInt8] {
        var result = bytes
        while result.count > 1, result.first == 0 { result.removeFirst() }
        return result
    }
}
