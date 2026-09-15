import Foundation

/// Just enough DER to move RSA keys between the three formats that matter:
/// SSH's own wire encoding, PKCS#1, and PKCS#8.
///
/// Security.framework will build a `SecKey` from a PKCS#1 blob and nothing
/// else, and OpenSSH hands out keys in neither PKCS#1 nor PKCS#8 by default, so
/// converting between them is unavoidable. A whole ASN.1 library would be a
/// large dependency for four tag types; `swift-asn1` is already in the
/// dependency graph (swift-crypto pulls it) but its API is deliberately not
/// public to us.
///
/// Reading side: every length is bounds-checked and every failure returns an
/// error. These bytes come from a file a user pasted in.
enum DER {
    enum Tag: UInt8 {
        case integer = 0x02
        case bitString = 0x03
        case octetString = 0x04
        case null = 0x05
        case objectIdentifier = 0x06
        case sequence = 0x30
    }

    enum Failure: Error, Equatable, LocalizedError {
        case truncated
        case unexpectedTag(expected: UInt8, found: UInt8)
        case lengthTooLarge
        case trailingBytes(Int)
        case negativeInteger

        var errorDescription: String? {
            switch self {
            case .truncated:
                return "The key data ends in the middle of a field."
            case .unexpectedTag(let expected, let found):
                return String(
                    format: "Expected an ASN.1 tag of 0x%02x but found 0x%02x.", expected, found
                )
            case .lengthTooLarge:
                return "A field in the key claims an implausible length."
            case .trailingBytes(let count):
                return "There are \(count) unexpected bytes after the key."
            case .negativeInteger:
                return "The key contains a negative integer where a modulus or exponent belongs."
            }
        }
    }

    // MARK: - Writing

    static func length(_ count: Int) -> Data {
        if count < 0x80 { return Data([UInt8(count)]) }
        var bytes: [UInt8] = []
        var remaining = count
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    static func encode(_ tag: Tag, _ content: Data) -> Data {
        var out = Data([tag.rawValue])
        out.append(Self.length(content.count))
        out.append(content)
        return out
    }

    /// A DER INTEGER holding a non-negative big-endian magnitude.
    ///
    /// Leading zero bytes are dropped, and one is added back when the top bit
    /// is set — otherwise the value reads as negative, which is how a perfectly
    /// good modulus becomes an unparseable key.
    static func integer(_ magnitude: Data) -> Data {
        var bytes = [UInt8](magnitude)
        while bytes.count > 1, bytes.first == 0 { bytes.removeFirst() }
        if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
        if bytes.isEmpty { bytes = [0] }
        return Self.encode(.integer, Data(bytes))
    }

    static func sequence(_ elements: [Data]) -> Data {
        Self.encode(.sequence, elements.reduce(into: Data()) { $0.append($1) })
    }

    // MARK: - Reading

    /// The contents of the single TLV that makes up `data`.
    ///
    /// Almost every DER structure here is "a SEQUENCE, then its fields", and
    /// `Reader.read` is mutating so it cannot be called on a temporary. This is
    /// the one-liner that unwraps the outer layer.
    static func contents(of tag: Tag, in data: Data) throws -> Data {
        var reader = Reader(data)
        return try reader.read(tag)
    }

    /// A cursor over a DER blob.
    struct Reader {
        private let bytes: [UInt8]
        private(set) var offset: Int

        init(_ data: Data) {
            self.bytes = [UInt8](data)
            self.offset = 0
        }

        var isAtEnd: Bool { self.offset >= self.bytes.count }
        var remaining: Int { max(0, self.bytes.count - self.offset) }

        /// Read one TLV and return its contents.
        mutating func read(_ tag: Tag) throws -> Data {
            guard self.offset < self.bytes.count else { throw Failure.truncated }
            let found = self.bytes[self.offset]
            guard found == tag.rawValue else {
                throw Failure.unexpectedTag(expected: tag.rawValue, found: found)
            }
            self.offset += 1
            let length = try self.readLength()
            guard self.remaining >= length else { throw Failure.truncated }
            defer { self.offset += length }
            return Data(self.bytes[self.offset..<(self.offset + length)])
        }

        /// Peek at the next tag without consuming it.
        func peekTag() -> UInt8? {
            self.offset < self.bytes.count ? self.bytes[self.offset] : nil
        }

        /// Read one TLV whatever its tag, returning the tag and the contents.
        ///
        /// Needed for the context-specific tags SEC 1 uses for the optional
        /// curve and public key (`[0]` and `[1]`), which have no entry in
        /// ``Tag``.
        mutating func readAny() throws -> (tag: UInt8, contents: Data) {
            guard self.offset < self.bytes.count else { throw Failure.truncated }
            let tag = self.bytes[self.offset]
            self.offset += 1
            let length = try self.readLength()
            guard self.remaining >= length else { throw Failure.truncated }
            defer { self.offset += length }
            return (tag, Data(self.bytes[self.offset..<(self.offset + length)]))
        }

        /// Skip one TLV of any tag.
        mutating func skipAny() throws {
            _ = try self.readAny()
        }

        /// Read an INTEGER as a non-negative big-endian magnitude.
        mutating func readInteger() throws -> Data {
            var value = [UInt8](try self.read(.integer))
            guard let first = value.first else { throw Failure.truncated }
            guard first & 0x80 == 0 else { throw Failure.negativeInteger }
            while value.count > 1, value.first == 0 { value.removeFirst() }
            return Data(value)
        }

        private mutating func readLength() throws -> Int {
            guard self.offset < self.bytes.count else { throw Failure.truncated }
            let first = self.bytes[self.offset]
            self.offset += 1
            if first & 0x80 == 0 { return Int(first) }
            let byteCount = Int(first & 0x7F)
            // A length needing more than four bytes would be over 4 GiB.
            guard byteCount > 0, byteCount <= 4, self.remaining >= byteCount else {
                throw Failure.lengthTooLarge
            }
            var length = 0
            for _ in 0..<byteCount {
                length = (length << 8) | Int(self.bytes[self.offset])
                self.offset += 1
            }
            return length
        }
    }
}
