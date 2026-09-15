import Foundation
import Network

/// One Bonjour advertisement, resolved to an address.
struct BonjourService: Equatable, Hashable, Sendable {
    /// Instance name as advertised, e.g. "noether".
    var name: String
    /// Service type, e.g. "_ssh._tcp".
    var type: String
    var address: String
    var port: Int

    /// `_ssh._tcp` → "ssh". What the results list shows as a chip.
    var shortType: String {
        type.hasPrefix("_") ? String(type.dropFirst().prefix(while: { $0 != "." })) : type
    }
}

/// Bonjour half of the scan.
///
/// Runs alongside the port sweep rather than before it: mDNS answers in
/// milliseconds from machines that advertise, and tells us *names*, which no
/// amount of knocking on ports will. The sweep finds the machines that stay
/// quiet; this finds the ones that introduce themselves.
enum BonjourDiscovery {
    /// Must match `NSBonjourServices` in Info.plist — iOS silently returns
    /// nothing for a type the app did not declare, which looks exactly like
    /// "no such service on this network".
    static let serviceTypes = [
        "_ssh._tcp",
        "_sftp-ssh._tcp",
        "_http._tcp",
        "_https._tcp",
        "_smb._tcp",
        "_workstation._tcp",
    ]

    private static let queue = DispatchQueue(label: "com.morton.ghostty.bonjour")

    /// Browse for `duration`, then resolve everything found to an IPv4 address.
    static func discover(
        types: [String] = serviceTypes,
        duration: TimeInterval = 5.0
    ) async -> [BonjourService] {
        let collector = EndpointCollector()

        let browsers = types.map { type -> NWBrowser in
            let parameters = NWParameters()
            parameters.includePeerToPeer = false
            let browser = NWBrowser(
                for: .bonjour(type: type, domain: nil),
                using: parameters
            )
            browser.browseResultsChangedHandler = { results, _ in
                collector.add(results.map(\.endpoint), type: type)
            }
            browser.start(queue: queue)
            return browser
        }

        try? await Task.sleep(nanoseconds: UInt64(duration * 1_000_000_000))
        browsers.forEach { $0.cancel() }

        let found = collector.drain()
        guard !found.isEmpty else { return [] }

        // Resolving is a connection each; keep a lid on how many at once.
        var services: [BonjourService] = []
        await withTaskGroup(of: BonjourService?.self) { group in
            var iterator = found.makeIterator()
            var inFlight = 0
            let limit = 16

            func addNext() -> Bool {
                guard let item = iterator.next() else { return false }
                group.addTask {
                    guard let resolved = await resolve(item.endpoint) else { return nil }
                    return BonjourService(
                        name: cleanName(item.name),
                        type: item.type,
                        address: resolved.address,
                        port: resolved.port
                    )
                }
                return true
            }

            while inFlight < limit, addNext() { inFlight += 1 }
            while let result = await group.next() {
                inFlight -= 1
                if let result { services.append(result) }
                if addNext() { inFlight += 1 }
            }
        }

        return services.sorted {
            ($0.address, $0.type, $0.name) < ($1.address, $1.type, $1.name)
        }
    }

    /// Bonjour instance names carry decoration: `_workstation._tcp` appends the
    /// MAC in brackets, and any name may contain escaped spaces.
    static func cleanName(_ raw: String) -> String {
        var name = raw.replacingOccurrences(of: "\\032", with: " ")
        if let bracket = name.range(of: " [", options: .backwards), name.hasSuffix("]") {
            name = String(name[name.startIndex..<bracket.lowerBound])
        }
        return name.trimmingCharacters(in: .whitespaces)
    }

    /// Turn a `.service` endpoint into an address.
    ///
    /// Network.framework has no resolve-without-connecting call, so this opens
    /// a connection and reads the path it established. `.waiting` counts: a
    /// refused connection has still told us who refused it.
    private static func resolve(
        _ endpoint: NWEndpoint,
        timeout: TimeInterval = 3.0
    ) async -> (address: String, port: Int)? {
        let parameters = NWParameters.tcp
        parameters.includePeerToPeer = false
        parameters.prohibitedInterfaceTypes = [.cellular]
        let connection = NWConnection(to: endpoint, using: parameters)

        let result: (address: String, port: Int)? = await withCheckedContinuation { continuation in
            let box = ResolveBox(continuation: continuation)

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready, .waiting:
                    box.finish(ipv4(of: connection.currentPath?.remoteEndpoint))
                    connection.cancel()
                case .failed, .cancelled:
                    box.finish(ipv4(of: connection.currentPath?.remoteEndpoint))
                default:
                    break
                }
            }
            connection.start(queue: queue)

            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                connection.cancel()
            }
        }

        connection.stateUpdateHandler = nil
        connection.cancel()
        return result
    }

    /// IPv4 only: the sweep enumerates an IPv4 subnet, so an address we cannot
    /// line up with a probe result is not useful here.
    static func ipv4(of endpoint: NWEndpoint?) -> (address: String, port: Int)? {
        guard case .hostPort(let host, let port) = endpoint else { return nil }
        guard case .ipv4(let address) = host else { return nil }
        // IPv4Address prints as "10.0.0.41%en0" when it carries a scope.
        let text = "\(address)".prefix(while: { $0 != "%" })
        guard !text.isEmpty else { return nil }
        return (String(text), Int(port.rawValue))
    }

    /// Accumulates browse results from several browsers on the browser queue.
    private final class EndpointCollector: @unchecked Sendable {
        struct Item: Hashable {
            let name: String
            let type: String
            let endpoint: NWEndpoint
        }

        private let lock = NSLock()
        private var items: Set<Item> = []

        func add(_ endpoints: [NWEndpoint], type: String) {
            lock.lock()
            defer { lock.unlock() }
            for endpoint in endpoints {
                guard case .service(let name, _, _, _) = endpoint else { continue }
                items.insert(Item(name: name, type: type, endpoint: endpoint))
            }
        }

        func drain() -> [Item] {
            lock.lock()
            defer { lock.unlock() }
            return Array(items)
        }
    }

    private final class ResolveBox: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<(address: String, port: Int)?, Never>?

        init(continuation: CheckedContinuation<(address: String, port: Int)?, Never>) {
            self.continuation = continuation
        }

        func finish(_ value: (address: String, port: Int)?) {
            lock.lock()
            let pending = continuation
            continuation = nil
            lock.unlock()
            pending?.resume(returning: value)
        }
    }
}
