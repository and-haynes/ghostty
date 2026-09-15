import Foundation
import Network

/// One TCP knock: connect, note whether anything answered, disconnect.
///
/// This is the whole of the scanner's "is something listening here?" logic. It
/// never sends a byte — the only data it ever reads is the identification
/// banner an SSH server volunteers before either side has said anything, which
/// is why reading it is not authentication and not a probe of any secret.
enum TCPProbe {
    /// How long to wait for a connection before calling the port closed. A LAN
    /// RTT is sub-millisecond; anything past a second is an address with
    /// nothing at it, and the ARP timeout is what we are really paying for.
    static let defaultTimeout: TimeInterval = 1.0
    /// An SSH banner arrives immediately or not at all.
    static let bannerTimeout: TimeInterval = 0.6

    private static let queue = DispatchQueue(label: "com.morton.ghostty.lanprobe", attributes: .concurrent)

    /// Returns the open port (with a banner, if one was offered) or nil.
    ///
    /// `readBanner` is only ever true for ports on the SSH list; a silent
    /// open port still counts as open, so a non-SSH server squatting on 22
    /// is reported rather than lost.
    static func probe(
        address: String,
        port: Int,
        timeout: TimeInterval = defaultTimeout,
        readBanner: Bool = false
    ) async -> LANOpenPort? {
        guard port > 0, port <= 65535, let endpointPort = NWEndpoint.Port(rawValue: UInt16(port))
        else { return nil }

        let options = NWProtocolTCP.Options()
        options.connectionTimeout = max(1, Int(timeout.rounded(.up)))
        options.noDelay = true
        let parameters = NWParameters(tls: nil, tcp: options)
        // Scanning over cellular would be someone else's network.
        parameters.prohibitedInterfaceTypes = [.cellular]

        let connection = NWConnection(
            host: NWEndpoint.Host(address),
            port: endpointPort,
            using: parameters
        )

        let outcome = await withCheckedContinuation { (continuation: CheckedContinuation<LANOpenPort?, Never>) in
            let box = ProbeBox(continuation: continuation)

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    box.markOpen(LANOpenPort(port: port, banner: nil))
                    guard readBanner else {
                        box.finish(LANOpenPort(port: port, banner: nil))
                        connection.cancel()
                        return
                    }
                    // Give the banner its own, shorter deadline: an open port
                    // that says nothing is still an open port.
                    let deadline = Task {
                        try? await Task.sleep(nanoseconds: UInt64(bannerTimeout * 1_000_000_000))
                        connection.cancel()
                    }
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, _, _, _ in
                        deadline.cancel()
                        box.finish(LANOpenPort(port: port, banner: data.flatMap(TCPProbe.banner(from:))))
                        connection.cancel()
                    }

                case .failed, .cancelled:
                    box.finishWithFallback()

                case .waiting:
                    // NWConnection parks in `.waiting` on ECONNREFUSED and
                    // friends, intending to retry. For a scanner a refusal is
                    // a final answer, and waiting out the retry would triple
                    // the sweep. Treat it as closed and move on.
                    box.finishWithFallback()
                    connection.cancel()

                case .setup, .preparing:
                    break

                @unknown default:
                    break
                }
            }

            connection.start(queue: queue)

            // Backstop: `.waiting` is not guaranteed for a black-holed address
            // (no RST, no ARP reply), so nothing above would ever fire.
            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                connection.cancel()
            }
        }

        connection.stateUpdateHandler = nil
        connection.cancel()
        return outcome
    }

    /// The first line of what a server volunteered, if it looks like a banner.
    ///
    /// Trimmed to one line and to printable ASCII: this string is rendered in
    /// a list row and stored in a host's notes, and a binary protocol's first
    /// bytes must not be able to smuggle escape sequences into either.
    static func banner(from data: Data) -> String? {
        guard !data.isEmpty else { return nil }
        let line = data.prefix(while: { $0 != 0x0a && $0 != 0x0d })
        guard !line.isEmpty else { return nil }
        let text = String(decoding: line, as: UTF8.self)
            .filter { $0.isASCII && !$0.unicodeScalars.contains { scalar in scalar.value < 0x20 } }
            .trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return nil }
        return String(text.prefix(120))
    }
}

/// Resumes a probe's continuation exactly once.
///
/// `NWConnection` will happily report `.cancelled` right after we have already
/// decided the answer, and resuming a continuation twice is a crash rather
/// than a warning — hence the lock and the flag rather than a bare capture.
private final class ProbeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<LANOpenPort?, Never>?
    /// What to report if the connection dies after we already saw it open.
    private var fallback: LANOpenPort?

    init(continuation: CheckedContinuation<LANOpenPort?, Never>) {
        self.continuation = continuation
    }

    func markOpen(_ value: LANOpenPort) {
        lock.lock()
        fallback = value
        lock.unlock()
    }

    func finish(_ value: LANOpenPort?) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
    }

    func finishWithFallback() {
        lock.lock()
        let pending = continuation
        continuation = nil
        let value = fallback
        lock.unlock()
        pending?.resume(returning: value)
    }
}

/// Reverse DNS for an address the scan already found.
///
/// Only ever asked about hosts that answered, so a sweep of a mostly-empty /24
/// does not also become a sweep of the resolver.
enum ReverseDNS {
    private static let queue = DispatchQueue(label: "com.morton.ghostty.lanrdns", attributes: .concurrent)

    static func name(for address: String, timeout: TimeInterval = 2.0) async -> String? {
        let resolved: String? = await withCheckedContinuation { continuation in
            let box = NameBox(continuation: continuation)
            queue.async {
                box.finish(Self.blockingLookup(address))
            }
            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                box.finish(nil)
            }
        }
        return resolved
    }

    /// `getnameinfo` with `NI_NAMEREQD`, so an address with no PTR record
    /// fails rather than handing back the address we already had.
    private static func blockingLookup(_ address: String) -> String? {
        var sin = sockaddr_in()
        sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sin.sin_family = sa_family_t(AF_INET)
        guard inet_pton(AF_INET, address, &sin.sin_addr) == 1 else { return nil }

        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status = withUnsafePointer(to: &sin) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                getnameinfo(
                    sockaddrPointer,
                    socklen_t(MemoryLayout<sockaddr_in>.size),
                    &buffer,
                    socklen_t(buffer.count),
                    nil,
                    0,
                    NI_NAMEREQD
                )
            }
        }
        guard status == 0 else { return nil }
        let name = String(cString: buffer)
        guard !name.isEmpty, name != address else { return nil }
        // "noether.lan." and "noether.lan" are the same machine.
        return name.hasSuffix(".") ? String(name.dropLast()) : name
    }

    private final class NameBox: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<String?, Never>?

        init(continuation: CheckedContinuation<String?, Never>) {
            self.continuation = continuation
        }

        func finish(_ value: String?) {
            lock.lock()
            let pending = continuation
            continuation = nil
            lock.unlock()
            pending?.resume(returning: value)
        }
    }
}
