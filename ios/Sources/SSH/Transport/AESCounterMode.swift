import CommonCrypto
import Crypto
import Foundation

/// Errors from the symmetric primitives this app has to supply itself.
/// swift-nio-ssh keeps `NIOSSHError`'s cases `internal`, so a transport
/// protection implemented outside the library cannot throw the library's own
/// errors. These stand in for them; NIOSSH treats any thrown error the same
/// way — it tears the connection down — and ours at least say what happened.
enum SSHCipherError: Error, Equatable {
    case badKeySize(expected: Int, actual: Int)
    case badIVSize(expected: Int, actual: Int)
    /// The packet framing does not match the negotiated scheme.
    case malformedPacket(String)
    /// CTR mode only ever sees whole cipher blocks in SSH; anything else means
    /// the packet framing is wrong and must not be decrypted "as far as it goes".
    case notBlockAligned(Int)
    case commonCryptoFailure(Int32)
    case macMismatch
}

/// AES in counter mode, as SSH's `aes128-ctr` / `aes192-ctr` / `aes256-ctr`.
///
/// CryptoKit has no CTR mode (it exposes only the AEADs), so the block cipher
/// comes from CommonCrypto. Rather than drive `CCCryptorCreateWithMode`'s own
/// CTR implementation — whose counter-endianness options have historically been
/// uneven across platforms — this keeps the counter itself in Swift and uses
/// CommonCrypto purely as an ECB block-encrypt oracle, which is the definition
/// of CTR mode:
///
/// ```text
/// keystream_i = AES-ENC(key, counter_i);  counter_{i+1} = counter_i + 1 (big-endian, mod 2^128)
/// ```
///
/// One `CCCryptor` is created per key and reused; ECB carries no chaining
/// state, so successive `CCCryptorUpdate` calls are independent and a whole
/// packet's worth of counter blocks can be encrypted in one call.
final class AESCounterMode {
    static let blockSize = 16

    private let cryptor: CCCryptorRef
    /// The 128-bit counter, big-endian, exactly as SSH's initial IV supplies it.
    private var counter: [UInt8]

    /// - Parameters:
    ///   - key: 16, 24 or 32 bytes.
    ///   - iv: the 16-byte initial counter block from key exchange.
    init(key: SymmetricKey, iv: [UInt8]) throws {
        let keyByteCount = key.bitCount / 8
        guard keyByteCount == kCCKeySizeAES128 || keyByteCount == kCCKeySizeAES192
            || keyByteCount == kCCKeySizeAES256
        else {
            throw SSHCipherError.badKeySize(expected: kCCKeySizeAES256, actual: keyByteCount)
        }
        guard iv.count == Self.blockSize else {
            throw SSHCipherError.badIVSize(expected: Self.blockSize, actual: iv.count)
        }

        var reference: CCCryptorRef?
        let status = key.withUnsafeBytes { keyPointer -> CCCryptorStatus in
            CCCryptorCreate(
                CCOperation(kCCEncrypt),
                CCAlgorithm(kCCAlgorithmAES),
                // ECB with no padding: the input is always a whole number of
                // counter blocks, and CTR does its own "padding" by truncation.
                CCOptions(kCCOptionECBMode),
                keyPointer.baseAddress,
                keyPointer.count,
                nil,
                &reference
            )
        }
        guard status == kCCSuccess, let reference else {
            throw SSHCipherError.commonCryptoFailure(status)
        }
        self.cryptor = reference
        self.counter = iv
    }

    deinit {
        CCCryptorRelease(self.cryptor)
    }

    /// XOR the keystream over `bytes` in place, advancing the counter.
    ///
    /// Encryption and decryption are the same operation. `bytes.count` must be
    /// a multiple of the block size — which, in SSH, it always is: the padding
    /// rules of RFC 4253 §6 guarantee the encrypted region of a packet is a
    /// whole number of cipher blocks.
    func apply(to bytes: UnsafeMutableRawBufferPointer) throws {
        guard bytes.count % Self.blockSize == 0 else {
            throw SSHCipherError.notBlockAligned(bytes.count)
        }
        guard bytes.count > 0 else { return }

        let blockCount = bytes.count / Self.blockSize
        var counterBlocks = [UInt8](repeating: 0, count: bytes.count)
        for block in 0..<blockCount {
            for byte in 0..<Self.blockSize {
                counterBlocks[block * Self.blockSize + byte] = self.counter[byte]
            }
            self.incrementCounter()
        }

        var keystream = [UInt8](repeating: 0, count: bytes.count)
        var moved = 0
        let status = counterBlocks.withUnsafeBytes { input -> CCCryptorStatus in
            keystream.withUnsafeMutableBytes { output -> CCCryptorStatus in
                CCCryptorUpdate(
                    self.cryptor,
                    input.baseAddress,
                    input.count,
                    output.baseAddress,
                    output.count,
                    &moved
                )
            }
        }
        guard status == kCCSuccess, moved == bytes.count else {
            throw SSHCipherError.commonCryptoFailure(status)
        }

        for index in 0..<bytes.count {
            bytes[index] ^= keystream[index]
        }
    }

    /// Convenience for tests and for callers holding an array.
    func apply(to bytes: inout [UInt8]) throws {
        try bytes.withUnsafeMutableBytes { try self.apply(to: $0) }
    }

    /// Big-endian increment of the whole 128-bit counter block, wrapping at
    /// 2^128 exactly as RFC 3686 §4 requires.
    private func incrementCounter() {
        var index = Self.blockSize - 1
        while index >= 0 {
            let (value, overflow) = self.counter[index].addingReportingOverflow(1)
            self.counter[index] = value
            if !overflow { return }
            index -= 1
        }
    }
}
