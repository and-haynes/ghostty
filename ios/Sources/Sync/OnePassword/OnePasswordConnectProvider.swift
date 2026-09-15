import Crypto
import Foundation

// MARK: - Transport seam

/// The one HTTP call the provider makes, behind a protocol.
///
/// Exists so the mapping logic — which is the part with bugs in it — can be
/// tested against hand-written Connect responses. A test that needs a live
/// 1Password Connect server is a test nobody runs.
protocol OnePasswordConnectTransport: AnyObject {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// `URLSession` transport, optionally tolerant of the server's own CA.
final class OnePasswordURLSessionTransport: OnePasswordConnectTransport {
    private let session: URLSession
    /// Kept alive explicitly: `URLSession` holds its delegate strongly until
    /// `invalidateAndCancel`, but the compiler does not know that, and losing
    /// it would silently drop us back to default TLS validation.
    private let tlsDelegate: OnePasswordConnectTLSDelegate?

    init(allowingSelfSignedCertificatesFor host: String?) {
        let configuration = URLSessionConfiguration.ephemeral
        // A Connect token is a bearer credential; nothing about this session
        // should survive in a shared cookie or URL cache.
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 20

        if let host, !host.isEmpty {
            let delegate = OnePasswordConnectTLSDelegate(host: host)
            self.tlsDelegate = delegate
            self.session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        } else {
            self.tlsDelegate = nil
            self.session = URLSession(configuration: configuration)
        }
    }

    deinit {
        // Ephemeral sessions leak their delegate and connection pool until
        // invalidated, and we create one per connect().
        session.finishTasksAndInvalidate()
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw VaultSyncError.badResponse("The reply was not an HTTP response.")
        }
        return (data, http)
    }
}

/// Accepts *any* server certificate, but only for one named host.
///
/// Why this exists: 1Password Connect is something you run yourself, and the
/// overwhelmingly common deployment is a container on a home LAN behind a
/// private CA or a self-signed certificate. Without an escape hatch the app is
/// simply unusable for those people, and the workaround they would reach for —
/// installing a CA profile on the phone — weakens *every* app on the device,
/// not just this one.
///
/// Why it is off by default, and scoped: turning this on trades authentication
/// of the server for reachability, which means anyone who can answer for that
/// hostname can collect the Connect token. That is a decision for the person
/// who owns the server to make explicitly, per host, with their eyes open — so
/// it is an opt-in flag, it never applies to a host the user did not configure,
/// and it does not touch any other authentication challenge (proxy auth,
/// client certificates) which fall through to the system's handling.
final class OnePasswordConnectTLSDelegate: NSObject, URLSessionDelegate {
    private let host: String

    init(host: String) {
        self.host = host
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              challenge.protectionSpace.host.caseInsensitiveCompare(host) == .orderedSame,
              let trust = challenge.protectionSpace.serverTrust
        else {
            // Anything else — a different host, a proxy, a client-certificate
            // request — gets the system's normal, strict behaviour.
            completionHandler(.performDefaultHandling, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

// MARK: - Connect wire types

/// `GET /v1/vaults` element.
struct OnePasswordVaultSummary: Codable, Equatable {
    var id: String
    var name: String?
}

/// `GET /v1/vaults/{id}/items` element. Summaries carry no `fields`, which is
/// why reading an item always costs a second request.
struct OnePasswordItemSummary: Codable, Equatable {
    var id: String
    var title: String?
    var category: String?
    var tags: [String]?
}

struct OnePasswordItemField: Codable, Equatable {
    var id: String?
    var label: String?
    var type: String?
    var value: String?
    var purpose: String?

    init(id: String? = nil, label: String? = nil, type: String? = nil, value: String? = nil, purpose: String? = nil) {
        self.id = id
        self.label = label
        self.type = type
        self.value = value
        self.purpose = purpose
    }
}

struct OnePasswordItem: Codable, Equatable {
    struct VaultRef: Codable, Equatable {
        var id: String
    }

    var id: String?
    var title: String?
    var category: String?
    var vault: VaultRef?
    var tags: [String]?
    var fields: [OnePasswordItemField]?

    /// Field lookup by Connect field id first, then by label.
    ///
    /// Ids are stable and are what 1Password's own SSH key items use
    /// (`private_key`, `public_key`, `fingerprint`); labels are what a human
    /// typing the item by hand would set. Accepting either means an item
    /// someone created in the 1Password app still reads.
    func field(id fieldID: String, label: String) -> OnePasswordItemField? {
        if let byID = fields?.first(where: { $0.id == fieldID }) { return byID }
        return fields?.first(where: { $0.label?.caseInsensitiveCompare(label) == .orderedSame })
    }

    var notesPlain: String? {
        if let byPurpose = fields?.first(where: { $0.purpose == "NOTES" })?.value { return byPurpose }
        return field(id: "notesPlain", label: "notesPlain")?.value
    }
}

// MARK: - Round-tripped metadata

/// What we stuff into an SSH key item's notes so a pull can rebuild the exact
/// `Identity` we pushed.
///
/// 1Password's SSH key category has fields for the key and its fingerprint and
/// nothing else — no place for a UUID, a creation date, or the biometry flag.
/// Losing those would mean every sync round-trip minted a new identity and
/// orphaned the host rows pointing at the old one.
private struct OnePasswordIdentityEnvelope: Codable {
    var schema: String
    var identity: Identity
}

/// What the single `Ghostty iOS hosts` secure note holds.
private struct OnePasswordHostsEnvelope: Codable {
    var schema: String?
    var hosts: [Host]
    var knownHosts: [KnownHost]
    var updatedAt: Date
}

// MARK: - Provider

/// Vault sync against a self-hosted **1Password Connect** server.
///
/// Connect is a REST front end you run yourself (a container, usually on your
/// own network) holding a credentials file for one or more vaults. The app
/// holds only its URL and a Connect token.
@MainActor
final class OnePasswordConnectProvider: VaultSyncProvider {
    let kind: VaultSyncProviderKind = .onePasswordConnect

    var helpText: String {
        "1Password has no on-device API — no app extension, no local vault "
            + "access, nothing an iOS app may call. The only supported way in is "
            + "1Password Connect: a small REST server you run yourself against "
            + "your own vault. Enter its URL and a Connect token; keys become "
            + "SSH Key items and your hosts become one secure note. If you don't "
            + "run Connect, use the encrypted bundle instead."
    }

    var status: VaultSyncStatus

    /// Trust the configured host's certificate even when the system won't.
    ///
    /// Off by default and deliberately so — see `OnePasswordConnectTLSDelegate`
    /// for the full reasoning. Set this before `connect`; it is read when the
    /// session is built.
    var allowsSelfSignedCertificates: Bool

    /// The item every Ghostty install writes its hosts into. Matched by exact
    /// title, so it must not be translated.
    static let hostsItemTitle = "Ghostty iOS hosts"

    /// Tag on every item we create. Only tagged items are ever updated or
    /// deleted, so a user's own SSH keys in the same vault are never touched.
    static let ghosttyTag = "ghostty-ios"

    private static let identitySchema = "ghostty.identity.v1"
    private static let hostsSchema = "ghostty.hosts.v1"

    /// Keychain account for the connection record. A Connect token is a bearer
    /// credential — anyone holding it can read the vault — so it lives in the
    /// Keychain, device-only, and never in UserDefaults where a device backup
    /// or a plist dump would expose it.
    private let credentialAccount = "sync.onepassword.connection"

    private struct StoredConnection: Codable {
        var serverURL: URL
        var token: String
        var vaultName: String?
    }

    private struct ActiveConnection {
        var serverURL: URL
        var token: String
        var vaultID: String
        var vaultName: String
    }

    private let keychain: KeychainStore
    /// Injected in tests; nil means "build a URLSession transport on connect".
    private let transportOverride: OnePasswordConnectTransport?
    private var transport: OnePasswordConnectTransport?
    private var connection: ActiveConnection?

    init(
        keychain: KeychainStore = SystemKeychain(),
        transport: OnePasswordConnectTransport? = nil,
        allowsSelfSignedCertificates: Bool = false
    ) {
        self.keychain = keychain
        self.transportOverride = transport
        self.allowsSelfSignedCertificates = allowsSelfSignedCertificates
        self.status = VaultSyncStatus()
    }

    // MARK: - Connect / disconnect

    func connect(_ credentials: VaultSyncCredentials) async throws {
        guard case .onePasswordConnect(let serverURL, let token, let vaultName) = credentials else {
            throw VaultSyncError.unsupportedCredentials(
                "1Password Connect needs your Connect server's URL and a Connect token."
            )
        }
        guard !token.isEmpty else {
            throw VaultSyncError.unsupportedCredentials("The Connect token is empty.")
        }

        let transport = makeTransport(for: serverURL)
        self.transport = transport

        // /heartbeat first: it separates "the server isn't there" from "the
        // token is wrong", which are very different things to tell a user.
        _ = try await Self.perform(
            "GET", path: "/heartbeat", body: nil,
            serverURL: serverURL, token: token, transport: transport
        )

        let vaultsData = try await Self.perform(
            "GET", path: "/v1/vaults", body: nil,
            serverURL: serverURL, token: token, transport: transport
        )
        let vaults = try Self.decodeJSON([OnePasswordVaultSummary].self, from: vaultsData, what: "the vault list")
        guard !vaults.isEmpty else {
            throw VaultSyncError.server(
                "That Connect token can't see any vaults. Check which vaults the token was issued for."
            )
        }

        let chosen: OnePasswordVaultSummary
        if let wanted = vaultName, !wanted.isEmpty {
            guard let match = vaults.first(where: { $0.name?.caseInsensitiveCompare(wanted) == .orderedSame }) else {
                let names = vaults.compactMap(\.name).joined(separator: ", ")
                throw VaultSyncError.server(
                    "No vault named “\(wanted)” is visible to that token. It can see: \(names.isEmpty ? "(unnamed vaults)" : names)."
                )
            }
            chosen = match
        } else {
            // No vault named: a Connect token is usually scoped to exactly one
            // vault, so the first is almost always the intended one.
            chosen = vaults[0]
        }

        let label = chosen.name ?? chosen.id
        connection = ActiveConnection(
            serverURL: serverURL,
            token: token,
            vaultID: chosen.id,
            vaultName: label
        )
        try storeCredentials(StoredConnection(serverURL: serverURL, token: token, vaultName: chosen.name))

        status.isConnected = true
        status.accountLabel = "\(label) · \(serverURL.host ?? serverURL.absoluteString)"
        status.lastResult = "Connected."
        status.lastResultWasError = false
    }

    func disconnect() async {
        connection = nil
        transport = nil
        // The token is the only thing worth erasing; nothing was written to
        // the Connect server that the user did not ask us to write, and
        // deleting their items on disconnect would be a nasty surprise.
        try? keychain.delete(account: credentialAccount)
        status = VaultSyncStatus()
    }

    /// Re-establish the connection from the stored token, e.g. after a relaunch.
    ///
    /// Returns false when nothing is stored. Separate from `connect` because it
    /// must not prompt and must not fail loudly: a Connect server that is off
    /// the network at launch is normal.
    @discardableResult
    func restoreConnection() async -> Bool {
        let storedData: Data?
        do {
            storedData = try keychain.get(account: credentialAccount, prompt: nil)
        } catch {
            return false
        }
        guard let storedData,
              let stored = try? JSONDecoder().decode(StoredConnection.self, from: storedData)
        else { return false }
        do {
            try await connect(
                .onePasswordConnect(
                    serverURL: stored.serverURL,
                    token: stored.token,
                    vaultName: stored.vaultName
                )
            )
            return true
        } catch {
            status.isConnected = false
            status.lastResult = error.localizedDescription
            status.lastResultWasError = true
            return false
        }
    }

    // MARK: - Push

    func push(_ snapshot: VaultSnapshot) async throws {
        let (connection, transport) = try requireConnection()
        let summaries = try await listItems(connection, transport: transport)

        var pushedKeys = 0
        var skipped = 0
        var liveTitles = Set<String>()

        for synced in snapshot.identities {
            // Secure Enclave keys have no exportable private half. Pushing the
            // metadata alone would put an item in the vault that looks like a
            // key and cannot authenticate anywhere.
            guard !synced.deviceOnly, let pem = synced.privateKeyPEM, !pem.isEmpty else {
                skipped += 1
                continue
            }
            let title = synced.identity.name
            liveTitles.insert(title)

            let existing = summaries.first {
                $0.category == "SSH_KEY" && $0.title == title
            }
            let item = try makeSSHKeyItem(
                for: synced,
                pem: pem,
                vaultID: connection.vaultID,
                existingID: existing?.id
            )
            try await upsert(item, existingID: existing?.id, connection: connection, transport: transport)
            pushedKeys += 1
        }

        // Hosts, known hosts and the snapshot clock ride in one secure note.
        // One item rather than one per host: hosts are not secrets, they change
        // together, and N round-trips over a home LAN is slow enough to notice.
        let existingHostsID = summaries.first {
            $0.category == "SECURE_NOTE" && $0.title == Self.hostsItemTitle
        }?.id
        let hostsItem = try makeHostsItem(
            snapshot: snapshot,
            vaultID: connection.vaultID,
            existingID: existingHostsID
        )
        try await upsert(hostsItem, existingID: existingHostsID, connection: connection, transport: transport)

        // Remove keys we previously pushed that the user has since deleted —
        // but only ones carrying our tag. An untagged SSH key in the same vault
        // belongs to the user, not to us.
        var deleted = 0
        for summary in summaries
        where summary.category == "SSH_KEY"
            && (summary.tags?.contains(Self.ghosttyTag) ?? false)
            && !liveTitles.contains(summary.title ?? "")
        {
            try await Self.perform(
                "DELETE",
                path: "/v1/vaults/\(Self.escape(connection.vaultID))/items/\(Self.escape(summary.id))",
                body: nil,
                serverURL: connection.serverURL,
                token: connection.token,
                transport: transport
            )
            deleted += 1
        }

        status.lastSync = Date()
        status.lastResultWasError = false
        status.lastResult = Self.pushSummary(
            keys: pushedKeys,
            hosts: snapshot.hosts.count,
            deleted: deleted,
            skipped: skipped
        )
    }

    /// "Pushed 2 keys and 3 hosts — 2 device-only keys not synced."
    static func pushSummary(keys: Int, hosts: Int, deleted: Int, skipped: Int) -> String {
        var text = "Pushed \(keys) key\(keys == 1 ? "" : "s") and \(hosts) host\(hosts == 1 ? "" : "s")"
        if deleted > 0 {
            text += ", removed \(deleted) stale item\(deleted == 1 ? "" : "s")"
        }
        if skipped > 0 {
            text += " — \(skipped) device-only key\(skipped == 1 ? "" : "s") not synced"
        }
        return text + "."
    }

    // MARK: - Pull

    func pull() async throws -> VaultSnapshot? {
        let (connection, transport) = try requireConnection()
        let summaries = try await listItems(connection, transport: transport)

        let hostsSummary = summaries.first { $0.category == "SECURE_NOTE" && $0.title == Self.hostsItemTitle }
        let keySummaries = summaries.filter { $0.category == "SSH_KEY" }

        // Nothing of ours in the vault yet: the engine treats nil as "no remote
        // state" and pushes the local vault as-is, rather than merging against
        // an empty snapshot and deleting everything.
        if hostsSummary == nil && keySummaries.isEmpty { return nil }

        var identities: [SyncedIdentity] = []
        var unreadable = 0
        for summary in keySummaries {
            let item = try await fetchItem(id: summary.id, connection: connection, transport: transport)
            if let synced = Self.identity(from: item) {
                identities.append(synced)
            } else {
                unreadable += 1
            }
        }

        var hosts: [Host] = []
        var knownHosts: [KnownHost] = []
        var updatedAt = Date.distantPast

        if let hostsSummary {
            let item = try await fetchItem(id: hostsSummary.id, connection: connection, transport: transport)
            guard let notes = item.notesPlain, let notesData = notes.data(using: .utf8) else {
                throw VaultSyncError.badResponse(
                    "The “\(Self.hostsItemTitle)” item has no notes. It may have been edited by hand."
                )
            }
            let envelope = try Self.decodeJSON(
                OnePasswordHostsEnvelope.self,
                from: notesData,
                what: "the “\(Self.hostsItemTitle)” note"
            )
            hosts = envelope.hosts
            knownHosts = envelope.knownHosts
            updatedAt = envelope.updatedAt
        } else {
            // Keys but no note: date the snapshot from the newest key we found
            // so "newest wins" still has a defensible clock rather than now(),
            // which would make the remote always beat local edits.
            updatedAt = identities.map(\.identity.createdAt).max() ?? .distantPast
        }

        let snapshot = VaultSnapshot(
            identities: identities,
            hosts: hosts,
            knownHosts: knownHosts,
            updatedAt: updatedAt
        )

        status.lastSync = Date()
        status.lastResultWasError = false
        status.lastResult = "Pulled \(snapshot.summary)"
            + (unreadable > 0 ? " — \(unreadable) item\(unreadable == 1 ? "" : "s") skipped (not a usable SSH key)." : ".")
        return snapshot
    }

    // MARK: - Mapping: our types -> Connect items

    private func makeSSHKeyItem(
        for synced: SyncedIdentity,
        pem: String,
        vaultID: String,
        existingID: String?
    ) throws -> OnePasswordItem {
        let envelope = OnePasswordIdentityEnvelope(
            schema: Self.identitySchema,
            identity: synced.identity
        )
        let metadata = try Self.encodeJSONString(envelope, what: "the key's metadata")

        return OnePasswordItem(
            id: existingID,
            title: synced.identity.name,
            category: "SSH_KEY",
            vault: .init(id: vaultID),
            tags: [Self.ghosttyTag],
            fields: [
                // Connect generates the `SSHKEY` field type itself and rejects
                // an attempt to create one, so we write CONCEALED (which it
                // accepts and which is still hidden in the UI) and accept
                // either type when reading back.
                OnePasswordItemField(
                    id: "private_key",
                    label: "private key",
                    type: "CONCEALED",
                    value: pem
                ),
                OnePasswordItemField(
                    id: "public_key",
                    label: "public key",
                    type: "STRING",
                    value: synced.identity.publicKeyLine
                ),
                OnePasswordItemField(
                    id: "fingerprint",
                    label: "fingerprint",
                    type: "STRING",
                    value: synced.identity.fingerprint
                ),
                OnePasswordItemField(
                    id: "notesPlain",
                    label: "notesPlain",
                    type: "STRING",
                    value: metadata,
                    purpose: "NOTES"
                ),
            ]
        )
    }

    private func makeHostsItem(
        snapshot: VaultSnapshot,
        vaultID: String,
        existingID: String?
    ) throws -> OnePasswordItem {
        let envelope = OnePasswordHostsEnvelope(
            schema: Self.hostsSchema,
            hosts: snapshot.hosts,
            knownHosts: snapshot.knownHosts,
            updatedAt: snapshot.updatedAt
        )
        let notes = try Self.encodeJSONString(envelope, what: "the hosts note")

        return OnePasswordItem(
            id: existingID,
            title: Self.hostsItemTitle,
            category: "SECURE_NOTE",
            vault: .init(id: vaultID),
            tags: [Self.ghosttyTag],
            fields: [
                OnePasswordItemField(
                    id: "notesPlain",
                    label: "notesPlain",
                    type: "STRING",
                    value: notes,
                    purpose: "NOTES"
                )
            ]
        )
    }

    // MARK: - Mapping: Connect items -> our types

    /// Rebuild a `SyncedIdentity` from an SSH key item.
    ///
    /// Reading is deliberately more generous than writing: an item written by
    /// us carries full metadata in its notes, but an SSH key the user created
    /// in the 1Password app has only the key, its public half and a
    /// fingerprint — and importing that is useful. Returns nil when the item
    /// has no private key or no recognisable algorithm, because an identity we
    /// cannot authenticate with is worse than no identity at all.
    static func identity(from item: OnePasswordItem) -> SyncedIdentity? {
        guard let pem = item.field(id: "private_key", label: "private key")?.value, !pem.isEmpty else {
            return nil
        }

        if let notes = item.notesPlain,
           let data = notes.data(using: .utf8),
           let envelope = try? decoder().decode(OnePasswordIdentityEnvelope.self, from: data),
           envelope.schema == identitySchema
        {
            return SyncedIdentity(identity: envelope.identity, privateKeyPEM: pem, deviceOnly: false)
        }

        // No metadata: synthesise it from the fields 1Password itself fills in.
        guard let publicLine = item.field(id: "public_key", label: "public key")?.value,
              !publicLine.isEmpty,
              let algorithm = publicLine.split(separator: " ").first.map(String.init),
              let keyType = SSHKeyType.allCases.first(where: {
                  !$0.isSecureEnclave && $0.opensshName == algorithm
              })
        else { return nil }

        let fingerprint = item.field(id: "fingerprint", label: "fingerprint")?.value
            ?? SSHFingerprint.sha256(publicKeyLine: publicLine)
            ?? ""

        let identity = Identity(
            // A random UUID here would mint a new identity on every pull and
            // orphan the host rows pointing at the previous one. Deriving it
            // from the immutable Connect item id keeps it stable.
            id: stableUUID(from: item.id ?? publicLine),
            name: item.title ?? "1Password key",
            keyType: keyType,
            publicKeyLine: publicLine,
            fingerprint: fingerprint,
            isSecureEnclave: false,
            requiresBiometrics: false,
            syncsToICloud: false
        )
        return SyncedIdentity(identity: identity, privateKeyPEM: pem, deviceOnly: false)
    }

    /// A stable, RFC-4122-shaped UUID derived from an arbitrary string.
    static func stableUUID(from string: String) -> UUID {
        var bytes = Array(SHA256.hash(data: Data(string.utf8)).prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x40  // version 4
        bytes[8] = (bytes[8] & 0x3F) | 0x80  // RFC 4122 variant
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }

    // MARK: - Requests

    private func requireConnection() throws -> (ActiveConnection, OnePasswordConnectTransport) {
        guard let connection, let transport, status.isConnected else {
            throw VaultSyncError.notConnected(displayName)
        }
        return (connection, transport)
    }

    private func makeTransport(for serverURL: URL) -> OnePasswordConnectTransport {
        if let transportOverride { return transportOverride }
        return OnePasswordURLSessionTransport(
            allowingSelfSignedCertificatesFor: allowsSelfSignedCertificates ? serverURL.host : nil
        )
    }

    private func listItems(
        _ connection: ActiveConnection,
        transport: OnePasswordConnectTransport
    ) async throws -> [OnePasswordItemSummary] {
        let data = try await Self.perform(
            "GET",
            path: "/v1/vaults/\(Self.escape(connection.vaultID))/items",
            body: nil,
            serverURL: connection.serverURL,
            token: connection.token,
            transport: transport
        )
        return try Self.decodeJSON([OnePasswordItemSummary].self, from: data, what: "the item list")
    }

    private func fetchItem(
        id: String,
        connection: ActiveConnection,
        transport: OnePasswordConnectTransport
    ) async throws -> OnePasswordItem {
        let data = try await Self.perform(
            "GET",
            path: "/v1/vaults/\(Self.escape(connection.vaultID))/items/\(Self.escape(id))",
            body: nil,
            serverURL: connection.serverURL,
            token: connection.token,
            transport: transport
        )
        return try Self.decodeJSON(OnePasswordItem.self, from: data, what: "an item")
    }

    private func upsert(
        _ item: OnePasswordItem,
        existingID: String?,
        connection: ActiveConnection,
        transport: OnePasswordConnectTransport
    ) async throws {
        let body = try Self.encodeJSON(item, what: "the item")
        let base = "/v1/vaults/\(Self.escape(connection.vaultID))/items"
        if let existingID {
            // PUT replaces the whole item; Connect has no PATCH, which is why
            // every field is rebuilt on each push.
            try await Self.perform(
                "PUT", path: "\(base)/\(Self.escape(existingID))", body: body,
                serverURL: connection.serverURL, token: connection.token, transport: transport
            )
        } else {
            try await Self.perform(
                "POST", path: base, body: body,
                serverURL: connection.serverURL, token: connection.token, transport: transport
            )
        }
    }

    @discardableResult
    private static func perform(
        _ method: String,
        path: String,
        body: Data?,
        serverURL: URL,
        token: String,
        transport: OnePasswordConnectTransport
    ) async throws -> Data {
        guard let url = makeURL(serverURL: serverURL, path: path) else {
            throw VaultSyncError.server("“\(serverURL.absoluteString)” is not a usable Connect server URL.")
        }

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        let (data, response): (Data, HTTPURLResponse)
        do {
            (data, response) = try await transport.send(request)
        } catch let error as VaultSyncError {
            throw error
        } catch let error as URLError where error.code == .cancelled {
            throw VaultSyncError.cancelled
        } catch let error as URLError where error.code == .serverCertificateUntrusted
            || error.code == .serverCertificateHasBadDate
            || error.code == .serverCertificateHasUnknownRoot
            || error.code == .serverCertificateNotYetValid
        {
            throw VaultSyncError.server(
                "The Connect server's certificate isn't trusted by this device. "
                    + "If you run it yourself with a private CA, turn on “Allow self-signed certificate” "
                    + "for this server."
            )
        } catch {
            throw VaultSyncError.server(
                "Couldn't reach the Connect server at \(serverURL.host ?? serverURL.absoluteString): "
                    + error.localizedDescription
            )
        }

        switch response.statusCode {
        case 200..<300:
            return data
        case 401, 403:
            throw VaultSyncError.server(
                "The Connect server rejected the token. Check it hasn't expired and that it was "
                    + "issued for this vault."
            )
        case 404:
            throw VaultSyncError.server(
                "The Connect server returned “not found” for \(path). Check the server URL and the vault."
            )
        default:
            let detail = String(data: data, encoding: .utf8).map(Self.trim) ?? ""
            throw VaultSyncError.server(
                "The Connect server returned HTTP \(response.statusCode)\(detail.isEmpty ? "." : ": \(detail)")"
            )
        }
    }

    static func makeURL(serverURL: URL, path: String) -> URL? {
        // Deliberately string concatenation rather than appendingPathComponent:
        // the latter percent-escapes nothing and happily produces "//v1/..."
        // when the configured URL ends in a slash.
        var base = serverURL.absoluteString
        while base.hasSuffix("/") { base.removeLast() }
        return URL(string: base + path)
    }

    /// Percent-escape a single path segment (vault and item ids).
    static func escape(_ segment: String) -> String {
        segment.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? segment
    }

    private static func trim(_ text: String) -> String {
        let cleaned = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.count > 200 ? String(cleaned.prefix(200)) + "…" : cleaned
    }

    // MARK: - Credential storage

    private func storeCredentials(_ stored: StoredConnection) throws {
        let data = try JSONEncoder().encode(stored)
        // Device-only: a Connect token grants read/write to a whole vault, and
        // nothing about it should ride along to another device via iCloud.
        try keychain.set(data, account: credentialAccount, options: .deviceOnly)
    }

    // MARK: - JSON

    /// Matches `Vault`'s on-disk convention so a `Host` written here and a
    /// `Host` written to Application Support decode the same way.
    private static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    private static func decodeJSON<T: Decodable>(_ type: T.Type, from data: Data, what: String) throws -> T {
        do {
            return try decoder().decode(type, from: data)
        } catch {
            throw VaultSyncError.badResponse("Couldn't read \(what): \(error.localizedDescription)")
        }
    }

    private static func encodeJSON<T: Encodable>(_ value: T, what: String) throws -> Data {
        do {
            return try encoder().encode(value)
        } catch {
            throw VaultSyncError.badResponse("Couldn't build \(what): \(error.localizedDescription)")
        }
    }

    private static func encodeJSONString<T: Encodable>(_ value: T, what: String) throws -> String {
        let data = try encodeJSON(value, what: what)
        guard let text = String(data: data, encoding: .utf8) else {
            throw VaultSyncError.badResponse("Couldn't build \(what).")
        }
        return text
    }
}
