import Foundation

/// Turns scan results into vault records.
///
/// Lives here rather than in the view because it is the one part of the import
/// with rules worth stating and worth testing: SSH ports become hosts, nothing
/// else does, and re-importing after a re-scan refreshes rather than
/// duplicating.
@MainActor
enum LANImporter {
    struct Summary: Equatable {
        var hostsAdded = 0
        /// Already in the vault; `lastSeen` was bumped and nothing else.
        var hostsRefreshed = 0
        var servicesAdded = 0

        var isEmpty: Bool { hostsAdded == 0 && hostsRefreshed == 0 && servicesAdded == 0 }

        var description: String {
            guard !isEmpty else { return "Nothing to import." }
            var parts: [String] = []
            if hostsAdded > 0 { parts.append("\(hostsAdded) SSH host\(hostsAdded == 1 ? "" : "s")") }
            if hostsRefreshed > 0 { parts.append("\(hostsRefreshed) refreshed") }
            if servicesAdded > 0 {
                parts.append("\(servicesAdded) local service\(servicesAdded == 1 ? "" : "s")")
            }
            return parts.joined(separator: ", ") + "."
        }
    }

    /// `aliases` overrides the name per address, which is what the inline field
    /// in the results list writes into.
    @discardableResult
    static func `import`(
        _ results: [LANHost],
        into vault: Vault,
        username: String,
        term: String,
        aliases: [String: String] = [:]
    ) -> Summary {
        var summary = Summary()
        var services: [LocalService] = []

        for result in results {
            let alias = name(for: result, aliases: aliases)

            for open in result.sshPorts {
                // Matched on endpoint, not on alias: the alias is the one thing
                // the user is free to change, so keying on it would turn a
                // rename into a duplicate.
                if let existing = vault.hosts.first(
                    where: { $0.hostname == result.address && $0.port == open.port }
                ) {
                    vault.markSeen(existing, at: result.lastSeen)
                    summary.hostsRefreshed += 1
                    continue
                }

                let host = Host(
                    alias: alias,
                    hostname: result.address,
                    port: open.port,
                    username: username,
                    group: Host.localGroup,
                    tags: result.bonjourServices.isEmpty ? [] : ["bonjour"],
                    term: term,
                    // The banner names the server's SSH implementation and
                    // version, which is exactly what a note about a machine
                    // found by a scan should say.
                    notes: open.banner ?? "",
                    lastSeen: result.lastSeen
                )
                vault.upsert(host)
                summary.hostsAdded += 1
            }

            for open in result.otherPorts {
                services.append(
                    LocalService(
                        alias: alias,
                        address: result.address,
                        port: open.port,
                        serviceType: open.serviceName,
                        scheme: open.guess.scheme,
                        lastSeen: result.lastSeen
                    )
                )
            }
        }

        let before = vault.localServices.count
        vault.upsertLocalServices(services)
        summary.servicesAdded = vault.localServices.count - before
        return summary
    }

    /// Edited alias, else Bonjour or reverse-DNS name, else the address.
    static func name(for result: LANHost, aliases: [String: String]) -> String {
        let edited = (aliases[result.address] ?? "").trimmingCharacters(in: .whitespaces)
        if !edited.isEmpty { return edited }
        return result.displayName
    }

    /// Which of these results are worth offering a "Pin host keys" button for.
    static func sshHosts(in vault: Vault, matching results: [LANHost]) -> [Host] {
        let addresses = Set(results.map(\.address))
        return vault.localHosts.filter { addresses.contains($0.hostname) }
    }
}
