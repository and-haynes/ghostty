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

    /// The last non-fatal failure, for the UI to surface. Metadata writes and
    /// best-effort secret cleanups report here instead of throwing, so a
    /// failed save is visible rather than silent.
    @Published private(set) var lastError: String?

    private let keychain: KeychainStore
    let directory: URL

    private var identitiesURL: URL { directory.appendingPathComponent("identities.json") }
    private var hostsURL: URL { directory.appendingPathComponent("hosts.json") }
    private var knownHostsURL: URL { directory.appendingPathComponent("known_hosts.json") }

    // MARK: - Lifecycle

    init(keychain: KeychainStore = SystemKeychain(), directory: URL? = nil) {
        self.keychain = keychain
        self.directory = directory ?? Vault.defaultDirectory()
        createDirectoryIfNeeded()
        self.identities = load([Identity].self, from: identitiesURL) ?? []
        self.hosts = load([Host].self, from: hostsURL) ?? []
        self.knownHosts = load([KnownHost].self, from: knownHostsURL) ?? []
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

    func importIdentity(name: String, pem: String, syncToICloud: Bool = false) throws -> Identity {
        let parsed = try OpenSSHKeyFile.parse(pem: pem)
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
