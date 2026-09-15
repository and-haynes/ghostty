import Foundation

/// A TCP port worth knocking on, and what it probably is.
///
/// Curated rather than exhaustive: a full scan of 65k ports across a /24 is
/// tens of minutes of radio time on a phone. These are the ports a homelab
/// actually runs, ordered so the interesting ones answer first.
struct PortGuess: Equatable, Hashable, Sendable {
    let port: Int
    let service: String
    /// True when this port can be turned into a vault `Host`.
    let isSSH: Bool
    /// URL scheme for a service that is reachable from a browser, if any.
    let scheme: String?

    init(_ port: Int, _ service: String, isSSH: Bool = false, scheme: String? = nil) {
        self.port = port
        self.service = service
        self.isSSH = isSSH
        self.scheme = scheme
    }
}

enum PortCatalog {
    /// The curated list, in probe order.
    static let curated: [PortGuess] = [
        PortGuess(22, "SSH", isSSH: true),
        PortGuess(2222, "SSH (alt)", isSSH: true),
        PortGuess(22222, "SSH (alt)", isSSH: true),
        PortGuess(830, "NETCONF over SSH", isSSH: true),
        PortGuess(80, "HTTP", scheme: "http"),
        PortGuess(443, "HTTPS", scheme: "https"),
        PortGuess(8006, "Proxmox VE", scheme: "https"),
        PortGuess(8080, "HTTP (alt)", scheme: "http"),
        PortGuess(8443, "HTTPS (alt)", scheme: "https"),
        PortGuess(8096, "Jellyfin", scheme: "http"),
        PortGuess(8123, "Home Assistant", scheme: "http"),
        PortGuess(9090, "Cockpit / Prometheus", scheme: "https"),
        PortGuess(3000, "Grafana / dev server", scheme: "http"),
        PortGuess(5000, "HTTP (alt)", scheme: "http"),
        PortGuess(32400, "Plex", scheme: "http"),
        PortGuess(445, "SMB"),
        PortGuess(5900, "VNC"),
        PortGuess(3389, "RDP"),
    ]

    static func guess(for port: Int) -> PortGuess {
        curated.first { $0.port == port } ?? PortGuess(port, "unknown")
    }

    static func isSSH(_ port: Int) -> Bool { guess(for: port).isSSH }

    /// Ports 1–1024, for the "scan everything" option. Slow by construction.
    static var lowPorts: [Int] { Array(1...1024) }
}

/// One open port found on one host.
struct LANOpenPort: Equatable, Hashable, Codable, Sendable {
    var port: Int
    /// The `SSH-2.0-...` identification line, when the port spoke SSH.
    var banner: String?

    var guess: PortGuess { PortCatalog.guess(for: port) }
    var isSSH: Bool { guess.isSSH || (banner?.hasPrefix("SSH-") ?? false) }
    var serviceName: String {
        if let banner, banner.hasPrefix("SSH-") { return "SSH" }
        return guess.service
    }
}

/// A host the scan found something on.
struct LANHost: Equatable, Identifiable, Codable, Sendable {
    var id: String { address }
    var address: String
    /// Reverse DNS or Bonjour name, when either answered.
    var hostname: String?
    /// Bonjour service types advertised by this address.
    var bonjourServices: [String] = []
    var openPorts: [LANOpenPort] = []
    var lastSeen: Date = Date()

    var displayName: String { hostname ?? address }
    var sshPorts: [LANOpenPort] { openPorts.filter(\.isSSH).sorted { $0.port < $1.port } }
    var otherPorts: [LANOpenPort] { openPorts.filter { !$0.isSSH }.sorted { $0.port < $1.port } }
    var hasSSH: Bool { !sshPorts.isEmpty }

    /// Short summary for a results row.
    var summary: String {
        openPorts
            .sorted { $0.port < $1.port }
            .map { "\($0.port) \($0.serviceName)" }
            .joined(separator: " · ")
    }
}

/// Results accumulate across scans rather than replacing each other, so a
/// machine that was asleep during one sweep does not vanish from the list.
enum LANResultsMerge {
    static func merge(existing: [LANHost], incoming: [LANHost]) -> [LANHost] {
        var byAddress = Dictionary(uniqueKeysWithValues: existing.map { ($0.address, $0) })

        for host in incoming {
            guard var current = byAddress[host.address] else {
                byAddress[host.address] = host
                continue
            }
            // A newly-learned name is worth keeping; a scan that failed to
            // resolve one should not erase the name we already had.
            if let hostname = host.hostname { current.hostname = hostname }
            current.bonjourServices = Array(Set(current.bonjourServices).union(host.bonjourServices)).sorted()

            var ports = Dictionary(uniqueKeysWithValues: current.openPorts.map { ($0.port, $0) })
            for port in host.openPorts {
                if let existingPort = ports[port.port], port.banner == nil {
                    // Keep a banner we already read rather than dropping it
                    // because this sweep did not get one.
                    ports[port.port] = LANOpenPort(port: port.port, banner: existingPort.banner)
                } else {
                    ports[port.port] = port
                }
            }
            current.openPorts = ports.values.sorted { $0.port < $1.port }
            current.lastSeen = max(current.lastSeen, host.lastSeen)
            byAddress[host.address] = current
        }

        return byAddress.values.sorted { LANResultsMerge.addressLess($0.address, $1.address) }
    }

    /// Sort by numeric octets, so .2 comes before .10.
    static func addressLess(_ lhs: String, _ rhs: String) -> Bool {
        let left = lhs.split(separator: ".").compactMap { Int($0) }
        let right = rhs.split(separator: ".").compactMap { Int($0) }
        guard left.count == 4, right.count == 4 else { return lhs < rhs }
        for (a, b) in zip(left, right) where a != b { return a < b }
        return false
    }
}

/// A non-SSH service kept for reference and for the console's `open`.
struct LocalService: Identifiable, Codable, Hashable, Sendable {
    var id: UUID
    var alias: String
    var address: String
    var port: Int
    var serviceType: String
    var scheme: String?
    var lastSeen: Date

    init(
        id: UUID = UUID(),
        alias: String,
        address: String,
        port: Int,
        serviceType: String,
        scheme: String?,
        lastSeen: Date = Date()
    ) {
        self.id = id
        self.alias = alias
        self.address = address
        self.port = port
        self.serviceType = serviceType
        self.scheme = scheme
        self.lastSeen = lastSeen
    }

    /// "https://10.0.0.41:9090", or "10.0.0.41:445" for things a browser
    /// cannot open.
    var urlString: String {
        guard let scheme else { return "\(address):\(port)" }
        return "\(scheme)://\(address):\(port)"
    }

    var url: URL? { scheme == nil ? nil : URL(string: urlString) }
}
