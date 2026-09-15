import Foundation
import Crypto

// MARK: - Notes payloads

/// Our `Identity` metadata, round-tripped through the cipher's `notes` field.
///
/// Bitwarden's SSH-key item holds exactly three things — private key, public
/// key, fingerprint — and our `Identity` holds rather more. Rather than lose
/// the rest on every sync, or invent custom fields the Bitwarden apps would
/// render as noise, the extras ride in `notes` as JSON. `notes` is an
/// EncString like everything else, so this is not a place where secrets leak;
/// it is just less readable in the Bitwarden UI, which is the trade.
struct GhosttyIdentityNote: Codable, Equatable {
    /// Bumped when the shape changes; an unknown version is ignored rather
    /// than guessed at, and the identity is rebuilt from the key itself.
    static let currentVersion = 1
    /// Marks the cipher as ours. Nothing without this marker is ever deleted.
    static let appMarker = "ghostty-ios"

    var v: Int = currentVersion
    var app: String = appMarker
    var id: UUID
    var keyType: SSHKeyType
    var createdAt: Date
    var requiresBiometrics: Bool
    var syncsToICloud: Bool
    var deviceOnly: Bool

    var isOurs: Bool { app == Self.appMarker && v == Self.currentVersion }
}

/// Hosts and pinned host keys, as the body of one secure note.
///
/// One note rather than one cipher per host: hosts are a list the user edits as
/// a whole, they are small, and N ciphers would mean N round trips and N chances
/// to half-succeed. The cost is that two devices editing different hosts
/// between syncs collide at snapshot granularity — which is exactly the
/// "newest wins" rule `VaultSyncMerge` already documents.
struct GhosttyHostsNote: Codable, Equatable {
    static let currentVersion = 1

    var v: Int = currentVersion
    var app: String = GhosttyIdentityNote.appMarker
    var hosts: [Host]
    var knownHosts: [KnownHost]
    var updatedAt: Date
}

// MARK: - Persisted session

/// What `connect` saves so the next launch does not ask for the master
/// password again.
///
/// This holds the unwrapped 64-byte user key — the key to every secret in the
/// account — so it lives in the Keychain as a device-only item and nowhere
/// else. Never `UserDefaults`, never Application Support, never a log line.
struct BitwardenPersistedSession: Codable, Equatable {
    var serverURL: URL
    var email: String
    var accessToken: String?
    var accessTokenExpiry: Date?
    var refreshToken: String?
    /// 64 bytes: 32 AES + 32 HMAC.
    var userKey: Data
    var allowsSelfSignedCertificates: Bool
    var deviceIdentifier: String
}

// MARK: - Provider

/// How the provider builds its HTTP client. Injected so tests can supply a
/// recorded transport without the provider knowing about tests.
typealias BitwardenClientFactory = (BitwardenAPIClient.Configuration) throws -> BitwardenAPIClient

@MainActor
final class BitwardenSyncProvider: VaultSyncProvider {
    /// The exact name of the secure note holding hosts. Matched on the
    /// *decrypted* name, because the server only ever sees ciphertext and two
    /// encryptions of the same string never look alike.
    static let hostsNoteName = "Ghostty iOS hosts"
    static let keychainAccount = "sync.bitwarden.session"

    let kind: VaultSyncProviderKind = .bitwarden

    var helpText: String {
        "Stores keys as Bitwarden SSH-key items and hosts as one secure note, encrypted on this "
        + "device before it is sent. Works with Bitwarden's servers or your own Vaultwarden."
    }

    var status: VaultSyncStatus = .disconnected

    /// Relax TLS validation for the configured server's host only.
    ///
    /// Surfaced in Settings as a per-server toggle, not a build flag, because
    /// the person who knows whether `vault.lan` is really their server is the
    /// user. See `BitwardenTLSDelegate` for the full argument.
    var allowsSelfSignedCertificates = false

    private let keychain: KeychainStore
    private let makeClient: BitwardenClientFactory
    private let argon2: Argon2Hashing

    private var client: BitwardenAPIClient?
    private var userKey: BitwardenSymmetricKey?
    private var session: BitwardenPersistedSession?

    init(
        keychain: KeychainStore = SystemKeychain(),
        argon2: Argon2Hashing = Argon2Unavailable(),
        makeClient: @escaping BitwardenClientFactory = { try BitwardenAPIClient(configuration: $0) }
    ) {
        self.keychain = keychain
        self.argon2 = argon2
        self.makeClient = makeClient
        // A failed restore is not an error worth surfacing at construction
        // time — it just means "not connected", which is the initial state.
        restoreSession()
    }

    // MARK: Connect

    func connect(_ credentials: VaultSyncCredentials) async throws {
        do {
            switch credentials {
            case .bitwardenPassword(let serverURL, let email, let masterPassword, let totp):
                try await connectWithPassword(
                    serverURL: serverURL,
                    email: email,
                    masterPassword: masterPassword,
                    totp: totp
                )
            case .bitwardenAPIKey(let serverURL, let clientID, let clientSecret, let masterPassword):
                try await connectWithAPIKey(
                    serverURL: serverURL,
                    clientID: clientID,
                    clientSecret: clientSecret,
                    masterPassword: masterPassword
                )
            default:
                throw VaultSyncError.unsupportedCredentials(
                    "Bitwarden needs either a master password or a personal API key."
                )
            }
        } catch {
            // Leave no half-connected state behind: a provider that reports
            // connected but has no user key fails later, further from the cause.
            client = nil
            userKey = nil
            session = nil
            record(error: error, while: "connecting")
            throw error
        }
    }

    private func connectWithPassword(
        serverURL: URL,
        email: String,
        masterPassword: String,
        totp: String?
    ) async throws {
        let configuration = makeConfiguration(serverURL: serverURL)
        let client = try makeClient(configuration)

        let prelogin = try await client.prelogin(email: email)
        let kdf = try prelogin.kdfDescriptor()
        let masterKey = try BitwardenCrypto.masterKey(
            password: masterPassword,
            email: email,
            kdf: kdf,
            argon2: argon2
        )
        let hash = try BitwardenCrypto.masterPasswordHash(masterKey: masterKey, password: masterPassword)
        let token = try await client.login(email: email, masterPasswordHash: hash, totp: totp)

        try await finishConnecting(
            client: client,
            configuration: configuration,
            email: email,
            masterKey: masterKey,
            protectedKey: token.key
        )
    }

    private func connectWithAPIKey(
        serverURL: URL,
        clientID: String,
        clientSecret: String,
        masterPassword: String
    ) async throws {
        let configuration = makeConfiguration(serverURL: serverURL)
        let client = try makeClient(configuration)

        // The API key authenticates the *session*; it does not unlock the
        // vault. The master password is still required to derive the key that
        // decrypts anything — which is the whole point of a zero-knowledge
        // design, and worth saying out loud because it surprises people.
        let token = try await client.loginWithAPIKey(clientID: clientID, clientSecret: clientSecret)

        // The client-credentials response has no email, so the account has to
        // identify itself through a sync before the KDF salt is known.
        let remote = try await client.sync()
        guard let email = remote.profile?.email, !email.isEmpty else {
            throw VaultSyncError.badResponse(
                "The server did not say which account this API key belongs to, so the master key "
                + "cannot be derived."
            )
        }

        let kdf: BitwardenKDF
        if let kdfType = token.kdf, let iterations = token.kdfIterations {
            kdf = try BitwardenPrelogin(
                kdf: kdfType,
                kdfIterations: iterations,
                kdfMemory: token.kdfMemory,
                kdfParallelism: token.kdfParallelism
            ).kdfDescriptor()
        } else {
            kdf = try await client.prelogin(email: email).kdfDescriptor()
        }

        let masterKey = try BitwardenCrypto.masterKey(
            password: masterPassword,
            email: email,
            kdf: kdf,
            argon2: argon2
        )

        try await finishConnecting(
            client: client,
            configuration: configuration,
            email: email,
            masterKey: masterKey,
            protectedKey: token.key ?? remote.profile?.key
        )
    }

    /// Shared tail of both login flows: unwrap the user key, persist, report.
    private func finishConnecting(
        client: BitwardenAPIClient,
        configuration: BitwardenAPIClient.Configuration,
        email: String,
        masterKey: SymmetricKey,
        protectedKey: String?
    ) async throws {
        var wrapped = protectedKey
        if wrapped == nil || wrapped?.isEmpty == true {
            // Older self-hosted servers omit `Key` from the token response.
            wrapped = try await client.sync().profile?.key
        }
        guard let wrapped, !wrapped.isEmpty else {
            throw VaultSyncError.badResponse(
                "The server did not return this account's encrypted key, so the vault cannot be "
                + "opened."
            )
        }

        let stretched = BitwardenCrypto.stretch(masterKey: masterKey)
        let userKey = try BitwardenCrypto.unwrapUserKey(
            protectedKey: wrapped,
            stretchedMasterKey: stretched
        )

        let session = BitwardenPersistedSession(
            serverURL: configuration.serverURL,
            email: BitwardenCrypto.normalise(email: email),
            accessToken: await client.currentAccessToken(),
            accessTokenExpiry: await client.currentAccessTokenExpiry(),
            refreshToken: await client.currentRefreshToken(),
            userKey: userKey.concatenated,
            allowsSelfSignedCertificates: configuration.allowsSelfSignedCertificates,
            deviceIdentifier: configuration.deviceIdentifier
        )
        try persist(session)

        self.client = client
        self.userKey = userKey
        self.session = session

        let host = await client.host
        status.isConnected = true
        status.accountLabel = "\(session.email) · \(host)"
        status.lastResult = "Connected to \(host)."
        status.lastResultWasError = false
    }

    func disconnect() async {
        await client?.clearSession()
        client = nil
        userKey = nil
        session = nil
        // A failure to delete leaves key material behind, which matters more
        // than the disconnect appearing to succeed.
        do {
            try keychain.delete(account: Self.keychainAccount)
            status = .disconnected
        } catch {
            status = VaultSyncStatus(
                isConnected: false,
                accountLabel: nil,
                lastSync: status.lastSync,
                lastResult: "Disconnected, but the saved session could not be removed from the "
                    + "Keychain: \(error.localizedDescription)",
                lastResultWasError: true
            )
        }
    }

    // MARK: Push

    func push(_ snapshot: VaultSnapshot) async throws {
        let (client, userKey) = try requireConnection()
        do {
            let remote = try await client.sync()
            let ciphers = (remote.ciphers ?? []).filter { !$0.isDeleted }

            let skipped = snapshot.identities.filter { $0.deviceOnly || $0.privateKeyPEM == nil }
            let syncable = snapshot.identities.filter { !$0.deviceOnly && $0.privateKeyPEM != nil }

            let pushedKeys = try await pushIdentities(
                syncable,
                allIdentities: snapshot.identities,
                existing: ciphers,
                client: client,
                userKey: userKey
            )
            try await pushHostsNote(snapshot, existing: ciphers, client: client, userKey: userKey)

            status.lastSync = Date()
            status.lastResultWasError = false
            var sentence = "Pushed \(pushedKeys) key\(pushedKeys == 1 ? "" : "s"), "
                + "\(snapshot.hosts.count) host\(snapshot.hosts.count == 1 ? "" : "s")."
            if !skipped.isEmpty {
                // Counted and named, not silently dropped: a user who thinks a
                // Secure Enclave key is backed up will find out the hard way.
                sentence += " \(skipped.count) device-only key\(skipped.count == 1 ? "" : "s") "
                    + "not synced."
            }
            status.lastResult = sentence
        } catch {
            record(error: error, while: "pushing to Bitwarden")
            throw error
        }
    }

    private func pushIdentities(
        _ identities: [SyncedIdentity],
        allIdentities: [SyncedIdentity],
        existing: [BitwardenCipher],
        client: BitwardenAPIClient,
        userKey: BitwardenSymmetricKey
    ) async throws -> Int {
        // Index what is already there two ways. Our own ciphers are found by
        // the identity UUID in their note; ciphers created by the Bitwarden
        // apps have no note, so they are found by key fingerprint — otherwise
        // a pull-then-push would duplicate every key the user already had.
        var byIdentityID: [UUID: BitwardenCipher] = [:]
        var byFingerprint: [String: BitwardenCipher] = [:]
        var ours: [(cipher: BitwardenCipher, note: GhosttyIdentityNote)] = []

        for cipher in existing where cipher.kind == .sshKey {
            if let note = decodeIdentityNote(cipher, userKey: userKey) {
                byIdentityID[note.id] = cipher
                ours.append((cipher, note))
            }
            if let fingerprint = try? fingerprint(of: cipher, userKey: userKey) {
                byFingerprint[fingerprint] = cipher
            }
        }

        for synced in identities {
            let request = try makeSSHKeyRequest(synced, userKey: userKey)
            let match = byIdentityID[synced.identity.id] ?? byFingerprint[synced.identity.fingerprint]
            if let match, let id = match.id {
                _ = try await client.updateCipher(id: id, request)
            } else {
                _ = try await client.createCipher(request)
            }
        }

        // Deletions only propagate for ciphers we created. Removing an item a
        // user made in the Bitwarden app because it is absent from our snapshot
        // would be destroying data we were never asked to own.
        let liveIDs = Set(allIdentities.map { $0.identity.id })
        let liveFingerprints = Set(allIdentities.map { $0.identity.fingerprint })
        for (cipher, note) in ours {
            guard note.isOurs, let id = cipher.id else { continue }
            guard !liveIDs.contains(note.id) else { continue }
            if let fingerprint = try? fingerprint(of: cipher, userKey: userKey),
               liveFingerprints.contains(fingerprint) {
                continue
            }
            try await client.deleteCipher(id: id)
        }

        return identities.count
    }

    private func pushHostsNote(
        _ snapshot: VaultSnapshot,
        existing: [BitwardenCipher],
        client: BitwardenAPIClient,
        userKey: BitwardenSymmetricKey
    ) async throws {
        let payload = GhosttyHostsNote(
            hosts: snapshot.hosts,
            knownHosts: snapshot.knownHosts,
            updatedAt: snapshot.updatedAt
        )
        let body = try GhosttyJSON.encoder.encode(payload)

        let request = BitwardenCipherRequest(
            type: BitwardenCipher.Kind.secureNote.rawValue,
            name: try EncString.encrypt(Self.hostsNoteName, key: userKey).description,
            notes: try EncString.encrypt(body, key: userKey).description,
            secureNote: BitwardenCipher.SecureNote(type: 0)
        )

        if let note = findHostsNote(in: existing, userKey: userKey), let id = note.id {
            _ = try await client.updateCipher(id: id, request)
        } else {
            _ = try await client.createCipher(request)
        }
    }

    private func makeSSHKeyRequest(
        _ synced: SyncedIdentity,
        userKey: BitwardenSymmetricKey
    ) throws -> BitwardenCipherRequest {
        guard let pem = synced.privateKeyPEM else {
            // Callers filter these out; failing loudly beats writing a key
            // item with no key in it.
            throw VaultSyncError.crypto(
                "\"\(synced.identity.name)\" has no exportable private key and cannot be synced."
            )
        }
        let identity = synced.identity
        let note = GhosttyIdentityNote(
            id: identity.id,
            keyType: identity.keyType,
            createdAt: identity.createdAt,
            requiresBiometrics: identity.requiresBiometrics,
            syncsToICloud: identity.syncsToICloud,
            deviceOnly: synced.deviceOnly
        )

        return BitwardenCipherRequest(
            type: BitwardenCipher.Kind.sshKey.rawValue,
            name: try EncString.encrypt(identity.name, key: userKey).description,
            notes: try EncString.encrypt(try GhosttyJSON.encoder.encode(note), key: userKey).description,
            sshKey: BitwardenCipher.SSHKey(
                privateKey: try EncString.encrypt(pem, key: userKey).description,
                publicKey: try EncString.encrypt(identity.publicKeyLine, key: userKey).description,
                keyFingerprint: try EncString.encrypt(identity.fingerprint, key: userKey).description
            )
        )
    }

    // MARK: Pull

    func pull() async throws -> VaultSnapshot? {
        let (client, userKey) = try requireConnection()
        do {
            let remote = try await client.sync()
            let ciphers = (remote.ciphers ?? []).filter { !$0.isDeleted }

            var identities: [SyncedIdentity] = []
            var unreadable = 0
            for cipher in ciphers where cipher.kind == .sshKey {
                do {
                    identities.append(try decodeIdentity(cipher, userKey: userKey))
                } catch {
                    // One unreadable item — typically an organisation-owned
                    // cipher encrypted with a key this session never had —
                    // must not lose the user the rest of their vault.
                    unreadable += 1
                }
            }

            let hostsCipher = findHostsNote(in: ciphers, userKey: userKey)
            var hosts: [Host] = []
            var knownHosts: [KnownHost] = []
            var updatedAt: Date?

            if let hostsCipher {
                let note = try decodeHostsNote(hostsCipher, userKey: userKey)
                hosts = note.hosts
                knownHosts = note.knownHosts
                updatedAt = note.updatedAt
            }

            guard hostsCipher != nil || !identities.isEmpty else {
                status.lastSync = Date()
                status.lastResultWasError = false
                status.lastResult = "Nothing stored in this vault yet."
                return nil
            }

            let snapshot = VaultSnapshot(
                identities: identities,
                hosts: hosts,
                knownHosts: knownHosts,
                // Fall back to the newest server-side revision so a vault
                // written by an older build still compares sensibly.
                updatedAt: updatedAt ?? newestRevision(in: ciphers) ?? Date()
            )

            status.lastSync = Date()
            status.lastResultWasError = false
            status.lastResult = unreadable == 0
                ? "Pulled \(snapshot.summary)."
                : "Pulled \(snapshot.summary). \(unreadable) item\(unreadable == 1 ? "" : "s") "
                    + "could not be decrypted and were skipped."
            return snapshot
        } catch {
            record(error: error, while: "pulling from Bitwarden")
            throw error
        }
    }

    // MARK: Decoding

    func decodeIdentity(
        _ cipher: BitwardenCipher,
        userKey: BitwardenSymmetricKey
    ) throws -> SyncedIdentity {
        guard let sshKey = cipher.sshKey else {
            throw VaultSyncError.badResponse("An SSH-key item arrived with no key fields.")
        }
        guard let encryptedPrivate = sshKey.privateKey, !encryptedPrivate.isEmpty else {
            throw VaultSyncError.badResponse("An SSH-key item arrived with no private key.")
        }
        let pem = try EncString.parse(encryptedPrivate, field: "private key")
            .decryptToString(key: userKey, field: "private key")

        let name = try cipher.name.map {
            try EncString.parse($0, field: "item name").decryptToString(key: userKey, field: "item name")
        } ?? "Imported key"

        // Prefer the stored public key; derive it from the private half only
        // when it is missing, because deriving means parsing the PEM, and a
        // key type we cannot parse should still be listed rather than dropped.
        var publicKeyLine: String
        if let encryptedPublic = sshKey.publicKey, !encryptedPublic.isEmpty,
           let decoded = try? EncString.parse(encryptedPublic).decryptToString(key: userKey),
           !decoded.trimmingCharacters(in: .whitespaces).isEmpty {
            publicKeyLine = decoded
        } else {
            let parsed = try OpenSSHKeyFile.parse(pem: pem)
            publicKeyLine = parsed.material.publicKeyLine(comment: parsed.comment)
        }
        publicKeyLine = publicKeyLine.trimmingCharacters(in: .whitespacesAndNewlines)

        guard let fingerprint = SSHFingerprint.sha256(publicKeyLine: publicKeyLine) else {
            throw VaultSyncError.badResponse(
                "\"\(name)\" has a public key that is not an authorized_keys line."
            )
        }

        let note = decodeIdentityNote(cipher, userKey: userKey)
        let keyType = note?.keyType ?? Self.keyType(forPublicKeyLine: publicKeyLine)
        guard let keyType else {
            throw VaultSyncError.badResponse(
                "\"\(name)\" uses an SSH key algorithm Ghostty cannot use."
            )
        }

        let identity = Identity(
            // A cipher written by the Bitwarden app has no id of ours. Deriving
            // one from the cipher id keeps it stable across pulls, so the same
            // remote key is the same local key every time rather than a new
            // duplicate.
            id: note?.id ?? Self.stableIdentityID(forCipherID: cipher.id ?? publicKeyLine),
            name: name,
            keyType: keyType,
            publicKeyLine: publicKeyLine,
            fingerprint: fingerprint,
            createdAt: note?.createdAt ?? BitwardenDate.parse(cipher.revisionDate) ?? Date(),
            isSecureEnclave: false,
            requiresBiometrics: note?.requiresBiometrics ?? false,
            syncsToICloud: note?.syncsToICloud ?? false
        )

        // Anything that arrived over the wire has an exportable private half by
        // definition, so it is never `deviceOnly`.
        return SyncedIdentity(identity: identity, privateKeyPEM: pem, deviceOnly: false)
    }

    private func decodeIdentityNote(
        _ cipher: BitwardenCipher,
        userKey: BitwardenSymmetricKey
    ) -> GhosttyIdentityNote? {
        guard let notes = cipher.notes, !notes.isEmpty,
              let encString = EncString(notes),
              let data = try? encString.decrypt(key: userKey),
              let note = try? GhosttyJSON.decoder.decode(GhosttyIdentityNote.self, from: data)
        else { return nil }
        // A note the user typed themselves is not our metadata; ignore it
        // rather than let a stray JSON blob rename their key.
        return note.isOurs ? note : nil
    }

    func decodeHostsNote(
        _ cipher: BitwardenCipher,
        userKey: BitwardenSymmetricKey
    ) throws -> GhosttyHostsNote {
        guard let notes = cipher.notes, !notes.isEmpty else {
            throw VaultSyncError.badResponse(
                "The \"\(Self.hostsNoteName)\" note is empty. Push from a device that has your "
                + "hosts to repopulate it."
            )
        }
        let data = try EncString.parse(notes, field: "hosts note").decrypt(key: userKey)
        do {
            return try GhosttyJSON.decoder.decode(GhosttyHostsNote.self, from: data)
        } catch {
            throw VaultSyncError.badResponse(
                "The \"\(Self.hostsNoteName)\" note is not in a format this version understands "
                + "(\(error.localizedDescription))."
            )
        }
    }

    /// Find the hosts note by its *decrypted* name.
    ///
    /// Duplicates are possible if two devices created the note simultaneously.
    /// The lowest cipher id wins, deterministically, and the others are left
    /// alone — silently deleting a note that might hold the only copy of
    /// someone's hosts is not a call this code gets to make.
    private func findHostsNote(
        in ciphers: [BitwardenCipher],
        userKey: BitwardenSymmetricKey
    ) -> BitwardenCipher? {
        ciphers
            .filter { $0.kind == .secureNote }
            .filter { cipher in
                guard let name = cipher.name,
                      let decoded = try? EncString.parse(name).decryptToString(key: userKey)
                else { return false }
                return decoded == Self.hostsNoteName
            }
            .sorted { ($0.id ?? "") < ($1.id ?? "") }
            .first
    }

    private func fingerprint(
        of cipher: BitwardenCipher,
        userKey: BitwardenSymmetricKey
    ) throws -> String {
        if let encrypted = cipher.sshKey?.keyFingerprint, !encrypted.isEmpty,
           let decoded = try? EncString.parse(encrypted).decryptToString(key: userKey),
           decoded.hasPrefix("SHA256:") {
            return decoded
        }
        // Bitwarden stores the fingerprint as a convenience field; re-deriving
        // it from the public key is authoritative when it is absent or in some
        // other format (MD5, or unprefixed).
        guard let encryptedPublic = cipher.sshKey?.publicKey,
              let line = try? EncString.parse(encryptedPublic).decryptToString(key: userKey),
              let fingerprint = SSHFingerprint.sha256(publicKeyLine: line)
        else {
            throw VaultSyncError.badResponse("An SSH-key item has no usable public key.")
        }
        return fingerprint
    }

    private func newestRevision(in ciphers: [BitwardenCipher]) -> Date? {
        ciphers.compactMap { BitwardenDate.parse($0.revisionDate) }.max()
    }

    /// `nonisolated`: a pure function of its argument, and callers (tests,
    /// background importers) have no reason to hop to the main actor for it.
    nonisolated static func keyType(forPublicKeyLine line: String) -> SSHKeyType? {
        guard let algorithm = line.split(separator: " ").first.map(String.init) else { return nil }
        // `secureEnclaveP256` shares `ecdsa-sha2-nistp256` with `p256`; a key
        // that arrived over the network is by definition not in an Enclave.
        return SSHKeyType.allCases.first {
            !$0.isSecureEnclave && $0.opensshName == algorithm
        }
    }

    /// A stable UUID for a remote item that carries no id of ours.
    ///
    /// Not a real UUIDv5 (no namespace), but it satisfies the two properties
    /// that matter: same cipher gives the same UUID on every device, and the
    /// bits are laid out so the value is a well-formed version-4-shaped UUID.
    nonisolated static func stableIdentityID(forCipherID cipherID: String) -> UUID {
        var digest = Array(SHA256.hash(data: Data("ghostty.bitwarden.\(cipherID)".utf8)).prefix(16))
        digest[6] = (digest[6] & 0x0F) | 0x40
        digest[8] = (digest[8] & 0x3F) | 0x80
        return UUID(uuid: (
            digest[0], digest[1], digest[2], digest[3],
            digest[4], digest[5], digest[6], digest[7],
            digest[8], digest[9], digest[10], digest[11],
            digest[12], digest[13], digest[14], digest[15]
        ))
    }

    // MARK: Session persistence

    private func makeConfiguration(serverURL: URL) -> BitwardenAPIClient.Configuration {
        BitwardenAPIClient.Configuration(
            serverURL: serverURL,
            allowsSelfSignedCertificates: allowsSelfSignedCertificates,
            // Reuse the stored device id when reconnecting to the same server:
            // a new one on every connect leaves a trail of dead devices in the
            // account's session list and re-triggers "new device" emails.
            deviceIdentifier: session?.serverURL == serverURL
                ? (session?.deviceIdentifier ?? UUID().uuidString)
                : UUID().uuidString
        )
    }

    private func persist(_ session: BitwardenPersistedSession) throws {
        let data = try JSONEncoder().encode(session)
        try keychain.set(
            data,
            account: Self.keychainAccount,
            // Device-only and not synchronizable: this blob is the key to the
            // whole account, and replicating it through iCloud Keychain would
            // widen the blast radius of an iCloud compromise for no benefit —
            // the other device can log in for itself.
            options: KeychainItemOptions(
                accessibility: .whenUnlockedThisDeviceOnly,
                requiresBiometrics: false,
                synchronizable: false
            )
        )
    }

    /// Rebuild the connection from the Keychain, if there is one to rebuild.
    @discardableResult
    func restoreSession() -> Bool {
        guard let data = try? keychain.get(account: Self.keychainAccount, prompt: nil),
              let session = try? JSONDecoder().decode(BitwardenPersistedSession.self, from: data),
              let userKey = try? BitwardenSymmetricKey(concatenated: session.userKey)
        else { return false }

        allowsSelfSignedCertificates = session.allowsSelfSignedCertificates
        let configuration = BitwardenAPIClient.Configuration(
            serverURL: session.serverURL,
            allowsSelfSignedCertificates: session.allowsSelfSignedCertificates,
            deviceIdentifier: session.deviceIdentifier,
            // Handed in at construction, not adopted through a later `await`:
            // a pull started the instant the app launches must not race the
            // restore and find an unauthenticated client.
            restoredSession: BitwardenAPIClient.RestoredSession(
                accessToken: session.accessToken,
                accessTokenExpiry: session.accessTokenExpiry,
                refreshToken: session.refreshToken
            )
        )
        guard let client = try? makeClient(configuration) else { return false }

        self.client = client
        self.userKey = userKey
        self.session = session
        status.isConnected = true
        status.accountLabel = "\(session.email) · \(session.serverURL.host ?? "")"
        return true
    }

    private func requireConnection() throws -> (BitwardenAPIClient, BitwardenSymmetricKey) {
        guard let client, let userKey else {
            throw VaultSyncError.notConnected(kind.displayName)
        }
        return (client, userKey)
    }

    private func record(error: Error, while activity: String) {
        status.lastResultWasError = true
        let description = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        status.lastResult = "Failed while \(activity): \(description)"
    }
}

// MARK: - JSON for our own payloads

/// Coding for the JSON *we* put inside Bitwarden notes.
///
/// Deliberately separate from `BitwardenJSON`: that one normalises Bitwarden's
/// inconsistent casing, which would be actively wrong here — these are our
/// documents, we control their shape, and a key-mangling strategy would make
/// the format depend on a helper meant for someone else's API.
enum GhosttyJSON {
    /// ISO-8601 with milliseconds. Readable by a human poking at the vault,
    /// and — unlike `Date`'s default of seconds-since-2001 — not silently
    /// meaningless to any other tool that opens the note.
    ///
    /// This **truncates `Date` to millisecond precision**, so a snapshot that
    /// makes a round trip through the vault is equal to the original only to
    /// the millisecond. That is deliberate and safe rather than merely
    /// tolerated: truncation always rounds *down*, so a pulled snapshot's
    /// `updatedAt` can never appear newer than the local one it came from, and
    /// `VaultSyncMerge`'s newest-wins rule therefore keeps the local copy on a
    /// tie instead of resurrecting a stale remote edit. Sub-millisecond
    /// precision on "when was this key created" is not information anyone has
    /// ever wanted.
    private static let formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(formatter.string(from: date))
        }
        return encoder
    }

    static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let text = try container.decode(String.self)
            guard let date = BitwardenDate.parse(text) else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "\"\(text)\" is not an ISO-8601 date."
                )
            }
            return date
        }
        return decoder
    }
}

/// Lenient ISO-8601 parsing.
///
/// Bitwarden's `revisionDate` comes back as `2026-09-14T12:00:00.0000000Z` —
/// seven fractional digits, which `ISO8601DateFormatter` rejects outright. Our
/// own notes use three. Both have to parse, and a date that fails to parse must
/// not take a whole sync down with it.
enum BitwardenDate {
    private static let fractional: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static let whole: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    static func parse(_ text: String?) -> Date? {
        guard let text, !text.isEmpty else { return nil }
        if let date = fractional.date(from: text) { return date }
        if let date = whole.date(from: text) { return date }
        // Truncate over-long fractional parts to the three digits the
        // formatter accepts, rather than losing the date entirely.
        if let dot = text.firstIndex(of: "."), let zone = text.lastIndex(where: {
            $0 == "Z" || $0 == "+" || $0 == "-"
        }), dot < zone {
            let fraction = text[text.index(after: dot)..<zone]
            let padded = String((fraction + "000").prefix(3))
            let rebuilt = text[text.startIndex..<dot] + "." + padded + text[zone...]
            return fractional.date(from: String(rebuilt))
        }
        return nil
    }
}
