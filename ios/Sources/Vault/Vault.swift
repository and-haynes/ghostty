import Foundation
import Combine

/// The vault: identities, saved hosts, and pinned host keys.
///
/// Split-brain storage on purpose. Secrets (private keys, host passwords) live
/// in the Keychain behind `KeychainStore`; everything else is plain JSON in
/// Application Support, so a backup, a diff, or a support request never
/// contains key material.
@MainActor
final class Vault: ObservableObject {
    @Published private(set) var identities: [Identity] = []
    @Published private(set) var hosts: [Host] = []
    @Published private(set) var knownHosts: [KnownHost] = []
    /// Non-SSH things a LAN scan found: web UIs, shares, screens. Kept for
    /// reference and for the console's `open`, not for connecting to.
    @Published private(set) var localServices: [LocalService] = []

    /// The last non-fatal failure, for the UI to surface. Metadata writes and
    /// best-effort secret cleanups report here instead of throwing, so a
    /// failed save is visible rather than silent.
    @Published private(set) var lastError: String?

    private let keychain: KeychainStore
    let directory: URL

    private var identitiesURL: URL { directory.appendingPathComponent("identities.json") }
    private var hostsURL: URL { directory.appendingPathComponent("hosts.json") }
    private var knownHostsURL: URL { directory.appendingPathComponent("known_hosts.json") }
    private var localServicesURL: URL { directory.appendingPathComponent("local_services.json") }

    // MARK: - Lifecycle

    init(keychain: KeychainStore = SystemKeychain(), directory: URL? = nil) {
        self.keychain = keychain
        self.directory = directory ?? Vault.defaultDirectory()
        createDirectoryIfNeeded()
        self.identities = load([Identity].self, from: identitiesURL) ?? []
        self.hosts = load([Host].self, from: hostsURL) ?? []
        self.knownHosts = load([KnownHost].self, from: knownHostsURL) ?? []
        self.localServices = load([LocalService].self, from: localServicesURL) ?? []
    }

    private static func defaultDirectory() -> URL {
        let fm = FileManager.default
        let base = (try? fm.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )) ?? fm.temporaryDirectory
        return base.appendingPathComponent("Ghostty", isDirectory: true)
    }

    private func createDirectoryIfNeeded() {
        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true
            )
        } catch {
            lastError = "Could not create the vault directory: \(error.localizedDescription)"
        }
    }

    // MARK: - Identities

    func generateIdentity(
        name: String,
        type: SSHKeyType,
        requiresBiometrics: Bool = false,
        syncToICloud: Bool = false
    ) throws -> Identity {
        let cleanName = try validatedName(name, excluding: nil)
        let material = try SSHPrivateKeyMaterial.generate(type, requiresBiometrics: requiresBiometrics)
        // Two reasons sync gets refused rather than merely ignored, so the
        // metadata never claims a protection the Keychain item does not have:
        // a Secure Enclave key's private half is a reference to *this* chip,
        // and a `.biometryCurrentSet` policy is tied to this device's enrolled
        // biometrics, which iCloud Keychain cannot replicate.
        let syncs = (type.isSecureEnclave || requiresBiometrics) ? false : syncToICloud

        let identity = Identity(
            name: cleanName,
            keyType: type,
            publicKeyLine: material.publicKeyLine(comment: cleanName),
            fingerprint: material.fingerprint,
            isSecureEnclave: type.isSecureEnclave,
            requiresBiometrics: requiresBiometrics,
            syncsToICloud: syncs
        )
        try store(material, for: identity)
        try appendIdentityRollingBackSecretOnFailure(identity)
        return identity
    }

    /// Import a private key in any encoding `PEMPrivateKey` understands.
    ///
    /// Routed through the format detector rather than straight into the
    /// `openssh-key-v1` parser: a key copied out of 1Password, exported from a
    /// cloud console or made by `openssl` is PKCS#8 or PKCS#1, and refusing
    /// those told the user to produce a format they had no way to produce
    /// (#008A1).
    func importIdentity(name: String, pem: String, syncToICloud: Bool = false) throws -> Identity {
        let parsed = try PEMPrivateKey.parse(pem)
        // Fall back to the key's own comment so importing a key with a blank
        // name still produces something recognisable in the list.
        let proposed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanName = try validatedName(
            proposed.isEmpty ? parsed.comment : proposed,
            excluding: nil
        )
        let identity = Identity(
            name: cleanName,
            keyType: parsed.material.keyType,
            // Keep the *original* comment: it is what appears in the
            // authorized_keys files this key is already deployed to.
            publicKeyLine: parsed.material.publicKeyLine(comment: parsed.comment),
            fingerprint: parsed.material.fingerprint,
            isSecureEnclave: false,
            requiresBiometrics: false,
            syncsToICloud: syncToICloud
        )
        try store(parsed.material, for: identity)
        try appendIdentityRollingBackSecretOnFailure(identity)
        return identity
    }

    func privateKey(for identity: Identity, prompt: String? = nil) throws -> SSHPrivateKeyMaterial {
        guard identities.contains(where: { $0.id == identity.id }) else {
            throw VaultError.identityNotFound
        }
        let effectivePrompt = prompt
            ?? (identity.requiresBiometrics ? "Unlock the key \"\(identity.name)\"" : nil)
        guard let data = try keychain.get(
            account: identity.keychainAccount,
            prompt: effectivePrompt
        ) else {
            // Metadata without a secret: the Keychain item was removed out from
            // under us (restore from a backup, or an iCloud item that has not
            // arrived yet).
            throw VaultError.identityNotFound
        }
        return try SSHPrivateKeyMaterial.restore(type: identity.keyType, data: data)
    }

    /// The key as an unencrypted OpenSSH PEM, for "copy private key" / share.
    func exportPrivateKey(for identity: Identity) throws -> String {
        guard !identity.isSecureEnclave else { throw VaultError.cannotExportSecureEnclaveKey }
        let material = try privateKey(for: identity, prompt: "Export the key \"\(identity.name)\"")
        return try OpenSSHKeyFile.encode(
            material: material,
            comment: Vault.comment(in: identity.publicKeyLine) ?? identity.name
        )
    }

    /// The `authorized_keys` line to paste on a server.
    func publicKeyLine(for identity: Identity) -> String { identity.publicKeyLine }

    func deleteIdentity(_ identity: Identity) throws {
        // Secret first: a leftover key with no metadata is invisible and
        // unreachable, whereas metadata with no secret is merely broken.
        try keychain.delete(account: identity.keychainAccount)
        identities.removeAll { $0.id == identity.id }
        // Hosts that pointed at this key fall back to password auth prompts
        // rather than silently referencing a key that no longer exists.
        for index in hosts.indices where hosts[index].identityID == identity.id {
            hosts[index].identityID = nil
        }
        try persistIdentities()
        try persistHosts()
    }

    @discardableResult
    func rename(_ identity: Identity, to newName: String) throws -> Identity {
        let cleanName = try validatedName(newName, excluding: identity.id)
        guard let index = identities.firstIndex(where: { $0.id == identity.id }) else {
            throw VaultError.identityNotFound
        }
        // `publicKeyLine` is deliberately untouched: its comment is already
        // deployed in remote authorized_keys files, and rewriting it here
        // would make the local copy disagree with every server.
        identities[index].name = cleanName
        try persistIdentities()
        return identities[index]
    }

    func identity(withID id: UUID?) -> Identity? {
        guard let id else { return nil }
        return identities.first { $0.id == id }
    }

    // MARK: - Hosts

    func upsert(_ host: Host) {
        if let index = hosts.firstIndex(where: { $0.id == host.id }) {
            hosts[index] = host
        } else {
            hosts.append(host)
        }
        record { try persistHosts() }
    }

    func deleteHost(_ host: Host) {
        hosts.removeAll { $0.id == host.id }
        // Never leave an orphaned password behind for a host the user believes
        // they deleted.
        record { try keychain.delete(account: host.keychainPasswordAccount) }
        record { try persistHosts() }
    }

    /// Store, or with `nil` clear, the host's password.
    func setPassword(_ password: String?, for host: Host) throws {
        guard let password, !password.isEmpty else {
            try keychain.delete(account: host.keychainPasswordAccount)
            setUsesPassword(false, for: host)
            return
        }
        // Passwords stay on this device: they are typed, not generated, and
        // are usually reused elsewhere.
        try keychain.set(
            Data(password.utf8),
            account: host.keychainPasswordAccount,
            options: KeychainItemOptions(accessibility: .whenUnlockedThisDeviceOnly)
        )
        setUsesPassword(true, for: host)
    }

    func password(for host: Host) throws -> String? {
        guard let data = try keychain.get(account: host.keychainPasswordAccount, prompt: nil) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func setUsesPassword(_ value: Bool, for host: Host) {
        guard let index = hosts.firstIndex(where: { $0.id == host.id }),
              hosts[index].usesPassword != value else { return }
        hosts[index].usesPassword = value
        record { try persistHosts() }
    }

    // MARK: - Known hosts (TOFU)

    func knownHost(hostname: String, port: Int) -> KnownHost? {
        let key = KnownHost.key(hostname: hostname, port: port)
        return knownHosts.first { $0.id == key }
    }

    /// Check a presented host key against the pin. Pure lookup + policy: it
    /// never writes, so a mismatch cannot be turned into a trust by accident.
    func verify(
        hostname: String,
        port: Int,
        presentedType: String,
        presentedFingerprint: String,
        presentedLine: String
    ) -> TOFUDecision {
        KnownHostsPolicy.decide(
            existing: knownHost(hostname: hostname, port: port),
            presentedType: presentedType,
            presentedFingerprint: presentedFingerprint,
            presentedLine: presentedLine
        )
    }

    /// Pin a host key. Called only after the user has explicitly accepted it —
    /// overwriting an existing pin here is how "I re-imaged that box" is
    /// handled, and it must stay a deliberate user action.
    @discardableResult
    func trust(
        hostname: String,
        port: Int,
        keyType: String,
        fingerprint: String,
        publicKeyLine: String
    ) throws -> KnownHost {
        let entry = KnownHost(
            hostname: hostname,
            port: port,
            keyType: keyType,
            fingerprint: fingerprint,
            publicKeyLine: publicKeyLine
        )
        if let index = knownHosts.firstIndex(where: { $0.id == entry.id }) {
            knownHosts[index] = entry
        } else {
            knownHosts.append(entry)
        }
        try persistKnownHosts()
        return entry
    }

    func forget(_ knownHost: KnownHost) {
        knownHosts.removeAll { $0.id == knownHost.id }
        record { try persistKnownHosts() }
    }

    // MARK: - Local services

    /// Merge scanned services in by (address, port) so a re-scan refreshes
    /// rather than duplicating, and a user-edited alias survives.
    func upsertLocalServices(_ incoming: [LocalService]) {
        for service in incoming {
            if let index = localServices.firstIndex(where: {
                $0.address == service.address && $0.port == service.port
            }) {
                localServices[index].lastSeen = service.lastSeen
                localServices[index].serviceType = service.serviceType
                localServices[index].scheme = service.scheme
            } else {
                localServices.append(service)
            }
        }
        // Numeric octet order, matching the results list: sorting addresses as
        // strings puts 10.0.0.100 above 10.0.0.41.
        localServices.sort {
            $0.address == $1.address
                ? $0.port < $1.port
                : LANResultsMerge.addressLess($0.address, $1.address)
        }
        record { try persistLocalServices() }
    }

    func renameLocalService(_ service: LocalService, to alias: String) {
        guard let index = localServices.firstIndex(where: { $0.id == service.id }) else { return }
        localServices[index].alias = alias
        record { try persistLocalServices() }
    }

    func deleteLocalService(_ service: LocalService) {
        localServices.removeAll { $0.id == service.id }
        record { try persistLocalServices() }
    }

    /// Hosts imported from a LAN scan.
    var localHosts: [Host] { hosts.filter { $0.group == Host.localGroup } }

    /// Record that a scan saw this host, without disturbing anything else.
    func markSeen(_ host: Host, at date: Date = Date()) {
        guard let index = hosts.firstIndex(where: { $0.id == host.id }) else { return }
        hosts[index].lastSeen = date
        record { try persistHosts() }
    }

    // MARK: - Sync

    /// Everything a sync provider should carry.
    ///
    /// A key whose private half cannot leave the device (Secure Enclave) is
    /// included as metadata with `deviceOnly` set rather than omitted: the
    /// other device should be able to *see* that the key exists and why it is
    /// not usable there, instead of silently missing a host's credential.
    func snapshot() -> VaultSnapshot {
        let synced = identities.map { identity -> SyncedIdentity in
            let pem = identity.isSecureEnclave ? nil : try? exportPrivateKey(for: identity)
            return SyncedIdentity(
                identity: identity,
                privateKeyPEM: pem,
                deviceOnly: identity.isSecureEnclave || pem == nil
            )
        }
        return VaultSnapshot(
            identities: synced,
            hosts: hosts,
            knownHosts: knownHosts,
            updatedAt: Date()
        )
    }

    /// Adopt a merged snapshot.
    ///
    /// Identities keep their original ids — a host references its key by id,
    /// so minting new ones on import would quietly unlink every host. A key
    /// that arrives without private material (device-only on the machine that
    /// exported it) is recorded as metadata only; attempting to use it will
    /// fail with "identity not found", which is the honest outcome.
    @discardableResult
    func apply(_ snapshot: VaultSnapshot) throws -> (keysAdded: Int, hostsAdded: Int, pinsAdded: Int) {
        var keysAdded = 0
        for incoming in snapshot.identities {
            if identities.contains(where: { $0.id == incoming.identity.id }) { continue }
            if let pem = incoming.privateKeyPEM {
                let parsed = try PEMPrivateKey.parse(pem)
                try store(parsed.material, for: incoming.identity)
            }
            identities.append(incoming.identity)
            keysAdded += 1
        }

        var hostsAdded = 0
        for host in snapshot.hosts where !hosts.contains(where: { $0.id == host.id }) {
            hosts.append(host)
            hostsAdded += 1
        }

        var pinsAdded = 0
        for pin in snapshot.knownHosts where !knownHosts.contains(where: { $0.id == pin.id }) {
            knownHosts.append(pin)
            pinsAdded += 1
        }

        try persistIdentities()
        try persistHosts()
        try persistKnownHosts()
        return (keysAdded, hostsAdded, pinsAdded)
    }

    /// Re-store an identity's secret with different Keychain attributes.
    /// Used by the iCloud provider to move a key between the local and the
    /// synchronised Keychain without the user regenerating it.
    func restoreProtection(for identity: Identity, syncToICloud: Bool) throws {
        guard !identity.isSecureEnclave else { return }
        let material = try privateKey(for: identity)
        guard let index = identities.firstIndex(where: { $0.id == identity.id }) else {
            throw VaultError.identityNotFound
        }
        identities[index].syncsToICloud = syncToICloud
        try store(material, for: identities[index])
        try persistIdentities()
    }

    // MARK: - Preview / first-run seed

    /// An in-memory vault with sample hosts, for SwiftUI previews and as the
    /// shape of the first-run seed. Deliberately not `#if DEBUG`: the app
    /// target uses it to populate an empty vault on first launch.
    static func preview() -> Vault {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("GhosttyPreview-\(UUID().uuidString)", isDirectory: true)
        let vault = Vault(keychain: InMemoryKeychain(), directory: directory)
        vault.hosts = [
            Host(
                alias: "noether",
                hostname: "10.0.0.81",
                username: "andy",
                group: "Homelab",
                tags: ["linux", "workspace"],
                colorHex: "#7C5CFF",
                notes: "Agent workspace — /srv/hl"
            ),
            Host(
                alias: "pi-a",
                hostname: "10.0.0.41",
                username: "andy",
                group: "Homelab",
                tags: ["raspberry-pi", "services"],
                colorHex: "#22C55E"
            ),
            Host(
                alias: "unas",
                hostname: "10.0.0.100",
                port: 22,
                username: "andy",
                group: "Storage",
                tags: ["nas"],
                colorHex: "#38BDF8"
            ),
        ]
        return vault
    }

    // MARK: - Naming

    private func validatedName(_ name: String, excluding id: UUID?) throws -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VaultError.malformedKey("A key needs a name.") }
        let clash = identities.contains {
            $0.id != id && $0.name.compare(trimmed, options: .caseInsensitive) == .orderedSame
        }
        guard !clash else { throw VaultError.duplicateName(trimmed) }
        return trimmed
    }

    /// Field 2 of an authorized_keys line, if present.
    private static func comment(in publicKeyLine: String) -> String? {
        let fields = publicKeyLine.split(
            separator: " ",
            maxSplits: 2,
            omittingEmptySubsequences: true
        )
        guard fields.count >= 3 else { return nil }
        return String(fields[2])
    }

    // MARK: - Secret storage

    private func store(_ material: SSHPrivateKeyMaterial, for identity: Identity) throws {
        try keychain.set(
            material.persistableData,
            account: identity.keychainAccount,
            options: KeychainItemOptions(
                accessibility: identity.syncsToICloud ? .whenUnlocked : .whenUnlockedThisDeviceOnly,
                requiresBiometrics: identity.requiresBiometrics,
                synchronizable: identity.syncsToICloud
            )
        )
    }

    /// Commit an identity, undoing the Keychain write if the metadata does not
    /// land — otherwise a failed save leaves an unreferenced secret forever.
    private func appendIdentityRollingBackSecretOnFailure(_ identity: Identity) throws {
        identities.append(identity)
        do {
            try persistIdentities()
        } catch {
            identities.removeAll { $0.id == identity.id }
            try? keychain.delete(account: identity.keychainAccount)
            throw error
        }
    }

    // MARK: - Persistence

    private func persistIdentities() throws { try write(identities, to: identitiesURL) }
    private func persistHosts() throws { try write(hosts, to: hostsURL) }
    private func persistKnownHosts() throws { try write(knownHosts, to: knownHostsURL) }
    private func persistLocalServices() throws { try write(localServices, to: localServicesURL) }

    private func write<T: Encodable>(_ value: T, to url: URL) throws {
        let encoder = JSONEncoder()
        // Sorted + pretty so these files read and diff like config, not blobs.
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(value)
        // .atomic: a crash mid-write must not leave a half-written vault.
        try data.write(to: url, options: .atomic)
    }

    private func load<T: Decodable>(_ type: T.Type, from url: URL) -> T? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            // Start empty rather than refusing to launch, but keep the file:
            // it is the only copy of the user's host list.
            quarantine(url)
            lastError = """
            \(url.lastPathComponent) could not be read and was set aside as a \
            ".corrupt" copy. That list has been reset.
            """
            return nil
        }
    }

    private func quarantine(_ url: URL) {
        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let destination = url.deletingLastPathComponent()
            .appendingPathComponent("\(url.lastPathComponent).corrupt-\(stamp)")
        try? FileManager.default.moveItem(at: url, to: destination)
    }

    /// Run a best-effort side effect, surfacing rather than swallowing failure.
    private func record(_ work: () throws -> Void) {
        do {
            try work()
        } catch {
            lastError = error.localizedDescription
        }
    }
}
