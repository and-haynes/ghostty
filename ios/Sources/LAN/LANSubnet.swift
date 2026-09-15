import Foundation

// The arithmetic half of the scanner: which addresses are worth knocking on.
// Deliberately free of Network, Darwin sockets and concurrency so the part
// most likely to be wrong — the bit twiddling — is testable without a radio.

/// An IPv4 subnet, derived from an interface's address and netmask.
struct LANSubnet: Equatable, Sendable {
    /// The interface's own address, host byte order.
    let address: UInt32
    /// Prefix length implied by the netmask, 0...32.
    let prefixLength: Int

    /// A scan wider than this is not a scan, it is a denial of service against
    /// your own Wi-Fi: a /22 is 1022 hosts × 18 ports, already ~70 s at the
    /// concurrency we use. Anything larger is clamped to a /22 around us.
    static let minimumPrefixLength = 22
    /// Below this we still scan, but say out loud how big the sweep got.
    static let warnBelowPrefixLength = 24

    init(address: UInt32, prefixLength: Int) {
        self.address = address
        self.prefixLength = min(max(prefixLength, 0), 32)
    }

    /// Parse dotted quads. Returns nil if either is not a well-formed IPv4
    /// address, or if the netmask is not a run of ones followed by zeroes —
    /// a discontiguous mask is not something we should guess about.
    init?(address: String, netmask: String) {
        guard let addr = LANSubnet.parse(address), let mask = LANSubnet.parse(netmask) else {
            return nil
        }
        guard let prefix = LANSubnet.prefixLength(ofMask: mask) else { return nil }
        self.init(address: addr, prefixLength: prefix)
    }

    /// The prefix we will actually sweep, after clamping.
    var effectivePrefixLength: Int { max(prefixLength, LANSubnet.minimumPrefixLength) }

    /// True when the real subnet is wider than we are willing to sweep.
    var isClamped: Bool { prefixLength < LANSubnet.minimumPrefixLength }

    /// True when the sweep is bigger than a /24 and the user should be told.
    var isLarge: Bool { effectivePrefixLength < LANSubnet.warnBelowPrefixLength }

    private var effectiveMask: UInt32 {
        LANSubnet.mask(forPrefixLength: effectivePrefixLength)
    }

    var networkAddress: UInt32 { address & effectiveMask }
    var broadcastAddress: UInt32 { networkAddress | ~effectiveMask }

    /// Dotted-quad rendering of the interface address, for the UI.
    var addressString: String { LANSubnet.string(from: address) }

    /// CIDR of the range we will sweep, e.g. "10.0.0.0/24".
    var cidr: String { "\(LANSubnet.string(from: networkAddress))/\(effectivePrefixLength)" }

    /// Every address to probe: the whole subnet minus the network and
    /// broadcast addresses, and minus our own — a phone answering its own
    /// knock is noise, not a discovery.
    ///
    /// `/31` and `/32` have no network/broadcast convention worth honouring
    /// here, so they yield their literal members instead of an empty list.
    func hostAddresses(excludingSelf: Bool = true) -> [String] {
        let prefix = effectivePrefixLength
        if prefix >= 31 {
            let all = (networkAddress...broadcastAddress).map(LANSubnet.string(from:))
            return excludingSelf ? all.filter { $0 != addressString } : all
        }

        var result: [String] = []
        result.reserveCapacity(Int(broadcastAddress - networkAddress))
        var current = networkAddress + 1
        while current < broadcastAddress {
            if !(excludingSelf && current == address) {
                result.append(LANSubnet.string(from: current))
            }
            current += 1
        }
        return result
    }

    /// How many probes a sweep of this subnet costs, for the warning text.
    func probeCount(ports: Int) -> Int { hostAddresses().count * ports }

    // MARK: - Conversions

    static func parse(_ dotted: String) -> UInt32? {
        let parts = dotted.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard let octet = UInt32(part), octet <= 255 else { return nil }
            value = (value << 8) | octet
        }
        return value
    }

    static func string(from value: UInt32) -> String {
        "\((value >> 24) & 0xff).\((value >> 16) & 0xff).\((value >> 8) & 0xff).\(value & 0xff)"
    }

    static func mask(forPrefixLength prefix: Int) -> UInt32 {
        prefix <= 0 ? 0 : (prefix >= 32 ? UInt32.max : ~(UInt32.max >> UInt32(prefix)))
    }

    /// Contiguous masks only — `255.255.0.255` gets nil rather than a guess.
    ///
    /// The prefix is 32 minus the run of trailing zeroes; rebuilding the mask
    /// from it and comparing is what rejects a discontiguous one.
    static func prefixLength(ofMask mask: UInt32) -> Int? {
        let trailingZeroes = mask == 0 ? 32 : mask.trailingZeroBitCount
        let prefix = 32 - trailingZeroes
        guard LANSubnet.mask(forPrefixLength: prefix) == mask else { return nil }
        return prefix
    }
}

/// The Wi-Fi interface this device is actually on.
///
/// `en0` is Wi-Fi on an iPhone and the host Mac's primary interface in the
/// simulator, which is why a simulator scan sees the real LAN. We look at
/// every running, non-loopback IPv4 interface and prefer `en0`, so a device on
/// Ethernet-over-USB or a Mac on `en1` still scans something sensible rather
/// than nothing.
enum LANInterface {
    struct Info: Equatable, Sendable {
        let name: String
        let address: String
        let netmask: String

        var subnet: LANSubnet? { LANSubnet(address: address, netmask: netmask) }
    }

    /// Ranked candidates, best first. Nil if the device has no usable IPv4.
    static func current() -> Info? { candidates().first }

    static func candidates() -> [Info] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var found: [Info] = []
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let flags = Int32(pointer.pointee.ifa_flags)
            guard flags & IFF_UP == IFF_UP, flags & IFF_LOOPBACK == 0 else { continue }
            guard let sockaddr = pointer.pointee.ifa_addr,
                sockaddr.pointee.sa_family == UInt8(AF_INET),
                let maskAddr = pointer.pointee.ifa_netmask
            else { continue }

            let name = String(cString: pointer.pointee.ifa_name)
            guard let address = describe(sockaddr), let netmask = describe(maskAddr) else { continue }
            // 169.254/16 means DHCP never answered; scanning it finds nothing.
            guard !address.hasPrefix("169.254.") else { continue }
            found.append(Info(name: name, address: address, netmask: netmask))
        }

        return found.sorted { rank($0.name) < rank($1.name) }
    }

    /// en0 first, then other `en*`, then everything else, ties by name.
    private static func rank(_ name: String) -> String {
        if name == "en0" { return "0\(name)" }
        if name.hasPrefix("en") { return "1\(name)" }
        return "2\(name)"
    }

    private static func describe(_ sockaddr: UnsafeMutablePointer<sockaddr>) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let result = getnameinfo(
            sockaddr,
            socklen_t(sockaddr.pointee.sa_len),
            &buffer,
            socklen_t(buffer.count),
            nil,
            0,
            NI_NUMERICHOST
        )
        guard result == 0 else { return nil }
        return String(cString: buffer)
    }
}
