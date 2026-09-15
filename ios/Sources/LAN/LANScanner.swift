import Foundation
import Network

/// Sweeps the local subnet for things worth connecting to.
///
/// Three sources run against one another and are reconciled by
/// `LANResultsMerge`:
///
/// * a **TCP sweep** of every address in the subnet across a curated port list
///   — finds machines that advertise nothing,
/// * **Bonjour** browsing — finds the machines that introduce themselves, and
///   is the only source of a friendly name on a network without reverse DNS,
/// * **reverse DNS**, asked only about addresses that answered.
///
/// It is a convenience, not a security tool. Nothing authenticates; the only
/// bytes read are the SSH identification banner a server volunteers before
/// either side has said anything.
@MainActor
final class LANScanner: ObservableObject {
    /// Results accumulate across scans — a machine that was asleep during one
    /// sweep should not vanish from the list.
    @Published private(set) var hosts: [LANHost] = []
    @Published private(set) var isScanning = false
    @Published private(set) var progress: Double = 0
    @Published private(set) var statusLine = ""
    /// Something the user should know but that did not stop the scan.
    @Published private(set) var warning: String?
    @Published private(set) var lastError: String?
    /// "en0 · 10.0.0.0/24 · 254 addresses", shown before and during a scan.
    @Published private(set) var subnetDescription: String?

    /// Enough sockets to keep a LAN busy, few enough to stay inside the
    /// per-process descriptor limit with room for the app's own connections.
    static let concurrency = 64

    private var task: Task<Void, Never>?
    private let bonjourDuration: TimeInterval
    private let probeTimeout: TimeInterval

    init(bonjourDuration: TimeInterval = 5.0, probeTimeout: TimeInterval = TCPProbe.defaultTimeout) {
        self.bonjourDuration = bonjourDuration
        self.probeTimeout = probeTimeout
        self.subnetDescription = LANScanner.describeInterface()
    }

    func cancel() {
        task?.cancel()
        task = nil
        isScanning = false
        statusLine = "Cancelled"
    }

    /// Clear accumulated results without touching anything already imported.
    func clear() {
        hosts = []
        progress = 0
        statusLine = ""
        warning = nil
        lastError = nil
    }

    /// Run one sweep. Awaiting this awaits the whole scan; `cancel()` stops it.
    func scan(ports: [Int]) async {
        guard !isScanning else { return }
        let running = Task { await self.run(ports: ports) }
        task = running
        await running.value
        task = nil
    }

    // MARK: - The sweep

    private func run(ports: [Int]) async {
        lastError = nil
        warning = nil
        progress = 0
        isScanning = true
        defer { isScanning = false }

        guard let interface = LANInterface.current(), let subnet = interface.subnet else {
            lastError = "No Wi-Fi network. Ghostty can only scan a network this device is on — "
                + "join Wi-Fi and try again."
            statusLine = ""
            return
        }

        let addresses = subnet.hostAddresses()
        subnetDescription = "\(interface.name) · \(subnet.cidr) · \(addresses.count) addresses"

        if subnet.isClamped {
            warning = "This network is a /\(subnet.prefixLength), which is too big to sweep. "
                + "Scanning the \(subnet.cidr) around this device instead."
        } else if subnet.isLarge {
            warning = "\(subnet.cidr) is \(addresses.count) addresses — "
                + "this will take a few minutes."
        }

        let uniquePorts = ports.reduced()
        guard !uniquePorts.isEmpty else {
            lastError = "No ports to scan."
            return
        }

        // Bonjour runs alongside the sweep; it answers in milliseconds and
        // there is no reason to make the user wait for it serially.
        let duration = bonjourDuration
        async let bonjour = BonjourDiscovery.discover(duration: duration)

        let found = await sweep(addresses: addresses, ports: uniquePorts, subnet: subnet)
        let advertised = await bonjour

        if Task.isCancelled {
            statusLine = "Cancelled — \(hosts.count) host\(hosts.count == 1 ? "" : "s") so far"
            return
        }

        statusLine = "Resolving names…"
        let named = await withNames(found)

        hosts = LANResultsMerge.merge(
            existing: hosts,
            incoming: LANResultsMerge.merge(existing: named, incoming: LANScanner.hosts(from: advertised))
        )
        progress = 1
        statusLine = "\(hosts.count) host\(hosts.count == 1 ? "" : "s") · "
            + "\(hosts.reduce(0) { $0 + $1.openPorts.count }) open ports"
        Haptics.shared.fire(hosts.isEmpty ? .syncFailed : .syncSucceeded)
    }

    /// The bounded-concurrency knock.
    ///
    /// Port-major order on purpose: the whole subnet gets knocked on 22 before
    /// anything gets knocked on 3389, so every SSH host in the results list is
    /// visible within the first few seconds of a scan that takes a minute.
    private func sweep(addresses: [String], ports: [Int], subnet: LANSubnet) async -> [LANHost] {
        var openPorts: [String: [LANOpenPort]] = [:]
        let total = addresses.count * ports.count
        guard total > 0 else { return [] }

        var pairs: [(address: String, port: Int)] = []
        pairs.reserveCapacity(total)
        for port in ports {
            for address in addresses { pairs.append((address, port)) }
        }

        let timeout = probeTimeout
        var completed = 0

        await withTaskGroup(of: (String, LANOpenPort?).self) { group in
            var next = 0

            func addTask() -> Bool {
                guard next < pairs.count else { return false }
                let pair = pairs[next]
                next += 1
                group.addTask {
                    let result = await TCPProbe.probe(
                        address: pair.address,
                        port: pair.port,
                        timeout: timeout,
                        readBanner: PortCatalog.isSSH(pair.port)
                    )
                    return (pair.address, result)
                }
                return true
            }

            var started = 0
            while started < LANScanner.concurrency, addTask() { started += 1 }

            while let (address, port) = await group.next() {
                completed += 1

                if let port {
                    openPorts[address, default: []].append(port)
                    // Publish as we go: a list that fills in is a progress
                    // indicator people actually read.
                    hosts = LANResultsMerge.merge(
                        existing: hosts,
                        incoming: LANScanner.hosts(from: openPorts)
                    )
                }

                if completed % 16 == 0 || completed == total {
                    progress = Double(completed) / Double(total)
                    statusLine = "\(subnet.cidr) · \(completed)/\(total) probes · "
                        + "\(openPorts.count) host\(openPorts.count == 1 ? "" : "s")"
                }

                if Task.isCancelled {
                    group.cancelAll()
                    continue
                }
                _ = addTask()
            }
        }

        return LANScanner.hosts(from: openPorts)
    }

    /// Reverse DNS, asked only about addresses that answered.
    private func withNames(_ found: [LANHost]) async -> [LANHost] {
        guard !found.isEmpty else { return [] }
        var named: [String: String] = [:]

        await withTaskGroup(of: (String, String?).self) { group in
            for host in found {
                group.addTask { (host.address, await ReverseDNS.name(for: host.address)) }
            }
            while let (address, name) = await group.next() {
                if let name { named[address] = name }
            }
        }

        return found.map { host in
            guard let name = named[host.address] else { return host }
            var copy = host
            copy.hostname = name
            return copy
        }
    }

    // MARK: - Shaping

    static func hosts(from openPorts: [String: [LANOpenPort]]) -> [LANHost] {
        openPorts
            .map { address, ports in
                LANHost(address: address, openPorts: ports.sorted { $0.port < $1.port })
            }
            .sorted { LANResultsMerge.addressLess($0.address, $1.address) }
    }

    /// Bonjour advertisements as scan results, so the merge has one shape to
    /// reconcile. An advertised port counts as open: the machine said so.
    static func hosts(from services: [BonjourService]) -> [LANHost] {
        var byAddress: [String: LANHost] = [:]
        for service in services {
            var host = byAddress[service.address]
                ?? LANHost(address: service.address, hostname: service.name)
            if host.hostname == nil { host.hostname = service.name }
            if !host.bonjourServices.contains(service.type) {
                host.bonjourServices.append(service.type)
            }
            if !host.openPorts.contains(where: { $0.port == service.port }) {
                host.openPorts.append(LANOpenPort(port: service.port, banner: nil))
            }
            byAddress[service.address] = host
        }
        return byAddress.values
            .map { host in
                var copy = host
                copy.bonjourServices.sort()
                copy.openPorts.sort { $0.port < $1.port }
                return copy
            }
            .sorted { LANResultsMerge.addressLess($0.address, $1.address) }
    }

    private static func describeInterface() -> String? {
        guard let interface = LANInterface.current(), let subnet = interface.subnet else { return nil }
        return "\(interface.name) · \(subnet.cidr) · \(subnet.hostAddresses().count) addresses"
    }
}

extension Array where Element == Int {
    /// De-duplicated, order preserved — a custom port list is typed by hand and
    /// "22, 22, 8080" should not knock twice.
    fileprivate func reduced() -> [Int] {
        var seen = Set<Int>()
        return filter { (1...65535).contains($0) && seen.insert($0).inserted }
    }
}

// MARK: - Rechecking hosts we already know about

extension LANScanner {
    /// Knock on exactly the endpoints of hosts already imported.
    ///
    /// This is what the Hosts tab's "Re-scan" does, and it is deliberately not
    /// a subnet sweep: the question there is "are the machines I kept awake?",
    /// which is `localHosts.count` probes rather than thousands.
    static func recheck(
        _ hosts: [Host],
        timeout: TimeInterval = TCPProbe.defaultTimeout
    ) async -> Set<UUID> {
        guard !hosts.isEmpty else { return [] }
        var reachable: Set<UUID> = []

        await withTaskGroup(of: (UUID, Bool).self) { group in
            for host in hosts {
                group.addTask {
                    let open = await TCPProbe.probe(
                        address: host.hostname,
                        port: host.port,
                        timeout: timeout,
                        readBanner: false
                    )
                    return (host.id, open != nil)
                }
            }
            while let (id, open) = await group.next() {
                if open { reachable.insert(id) }
            }
        }

        return reachable
    }
}
