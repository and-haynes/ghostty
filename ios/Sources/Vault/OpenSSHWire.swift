import Foundation

// MARK: - Writing

/// The SSH binary packet primitives from RFC 4251 §5.
///
/// Every length-prefixed field in an SSH key blob — algorithm names, curve
/// identifiers, public points, comments — is a `string`: a 4-byte big-endian
/// length followed by that many bytes. Integers are `mpint`: a string holding
/// a two's-complement big-endian number, which is why a positive value whose
/// top bit is set needs a leading zero byte so it does not read as negative.
enum OpenSSHWire {
    static func writeUInt32(_ value: UInt32) -> Data {
        Data([
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ])
    }

    static func writeString(_ data: Data) -> Data {
        var out = writeUInt32(UInt32(data.count))
        out.append(data)
        return out
    }

    static func writeString(_ string: String) -> Data {
        // SSH names are ASCII by spec; UTF-8 is a superset and is what
        // OpenSSH actually writes for comments.
        writeString(Data(string.utf8))
    }

    static func writeString(_ bytes: [UInt8]) -> Data {
        writeString(Data(bytes))
    }

    /// Encode a non-negative big-endian magnitude as an SSH `mpint`.
    ///
    /// Zero is the empty string, leading zero bytes are not transmitted, and a
    /// value with the high bit set gains one 0x00 byte so it stays positive.
    static func writeMPInt(_ magnitude: Data) -> Data {
        var bytes = [UInt8](magnitude)
        while let first = bytes.first, first == 0x00 { bytes.removeFirst() }
        guard let first = bytes.first else { return writeUInt32(0) }
        if first & 0x80 != 0 { bytes.insert(0x00, at: 0) }
        return writeString(Data(bytes))
    }

    /// Undo `writeMPInt` into a fixed-width big-endian scalar.
    ///
    /// CryptoKit's `rawRepresentation` initialisers demand exactly the curve's
    /// byte count, but an mpint is minimally encoded — a scalar that happens to
    /// start with a zero byte arrives short, and one with the high bit set
    /// arrives one byte long. Normalise both cases rather than hand CryptoKit
    /// something it will reject with an opaque error.
    static func mpintToFixedWidth(_ mpint: Data, byteCount: Int) -> Data? {
        var bytes = [UInt8](mpint)
        while let first = bytes.first, first == 0x00, bytes.count > byteCount {
            bytes.removeFirst()
        }
        guard bytes.count <= byteCount else { return nil }
        if bytes.count < byteCount {
            bytes.insert(contentsOf: [UInt8](repeating: 0, count: byteCount - bytes.count), at: 0)
        }
        return Data(bytes)
    }
}

// MARK: - Reading

/// A cursor over an SSH blob. Every read is bounds-checked and returns nil
/// rather than trapping — this parses untrusted file content, so a truncated
/// or hostile key must surface as an error, never as a crash.
struct OpenSSHWireReader {
    private let bytes: [UInt8]
    private(set) var offset: Int = 0

    init(_ data: Data) {
        // Re-base: a Data slice keeps its parent's indices, and integer
        // offsets into one are a classic source of off-by-startIndex bugs.
        self.bytes = [UInt8](data)
    }

    var isAtEnd: Bool { offset >= bytes.count }
    var bytesRemaining: Int { max(0, bytes.count - offset) }
    var remaining: Data { Data(bytes[min(offset, bytes.count)...]) }

    mutating func readBytes(_ count: Int) -> Data? {
        guard count >= 0, bytesRemaining >= count else { return nil }
        defer { offset += count }
        return Data(bytes[offset..<(offset + count)])
    }

    mutating func readUInt32() -> UInt32? {
        guard let raw = readBytes(4) else { return nil }
        return raw.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    mutating func readString() -> Data? {
        guard let length = readUInt32() else { return nil }
        // A 4 GiB field in a key file is a length-prefix attack, not a key.
        guard length <= 1 << 20 else { return nil }
        return readBytes(Int(length))
    }

    mutating func readStringUTF8() -> String? {
        guard let raw = readString() else { return nil }
        return String(data: raw, encoding: .utf8)
    }
}
