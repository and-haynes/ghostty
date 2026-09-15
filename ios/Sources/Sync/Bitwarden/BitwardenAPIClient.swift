import Foundation

// MARK: - Transport seam

/// One HTTP round trip.
///
/// The provider talks to this rather than to `URLSession` directly so tests can
/// replay recorded responses. A vault client that can only be exercised against
/// a live server is a vault client that is never exercised.
protocol BitwardenTransport: AnyObject {
    func send(_ request: URLRequest) async throws -> (data: Data, response: HTTPURLResponse)
}

/// The real transport.
final class URLSessionTransport: NSObject, BitwardenTransport {
    private let session: URLSession
    /// Held so the session can be torn down; `URLSession` retains its delegate
    /// until `invalidateAndCancel()`, which is a retain cycle if ignored.
    private let tlsDelegate: BitwardenTLSDelegate?

    /// - Parameter selfSignedHost: when non-nil, and only for this exact host,
    ///   an untrusted server certificate is accepted. See
    ///   `BitwardenTLSDelegate` for why this is opt-in.
    init(selfSignedHost: String? = nil, configuration: URLSessionConfiguration = .ephemeral) {
        // `.ephemeral`: no on-disk cache. Vault responses contain every
        // encrypted secret the account owns, and a URL cache file is not a
        // place to leave them even encrypted.
        let config = configuration
        config.httpShouldSetCookies = false
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData

        if let selfSignedHost {
            let delegate = BitwardenTLSDelegate(host: selfSignedHost)
            self.tlsDelegate = delegate
            self.session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        } else {
            self.tlsDelegate = nil
            self.session = URLSession(configuration: config)
        }
        super.init()
    }

    deinit {
        session.invalidateAndCancel()
    }

    func send(_ request: URLRequest) async throws -> (data: Data, response: HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw VaultSyncError.badResponse("The reply was not an HTTP response.")
        }
        return (data, http)
    }
}

// MARK: - TLS

/// Accepts an otherwise-untrusted server certificate for **one** host.
///
/// The homelab's `vault.lan` is signed by a private CA that iOS has no reason
/// to trust, and a user who cannot connect at all is a user who will not use
/// the feature. But this is exactly the switch that turns TLS into
/// decoration, so:
///
/// * It is **off by default** and must be turned on per connection.
/// * It is scoped to the single configured host. Every other host — including
///   any redirect target — goes through normal validation, so a compromised
///   DNS answer for `bitwarden.com` is still rejected.
/// * It is surfaced in the UI as a user-visible choice ("Trust this server's
///   certificate"), not buried in a build flag, because the person accepting
///   the risk should be the person who knows whether the server is theirs.
///
/// The properly boring alternative — and what should happen eventually — is
/// installing the homelab CA as a trusted root profile on the device, after
/// which this flag can stay off. Pinning the CA's public key here would be
/// better still; it is not done yet because the CA is not shipped with the app.
final class BitwardenTLSDelegate: NSObject, URLSessionDelegate {
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
              challenge.protectionSpace.host == host,
              let trust = challenge.protectionSpace.serverTrust
        else {
            // Anything that is not "the server I was told to expect presenting
            // a certificate" gets the system's own answer.
            completionHandler(.performDefaultHandling, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

// MARK: - Endpoints

/// Where the identity and API services live for a given server.
///
/// Self-hosted Bitwarden and Vaultwarden put both behind one origin as
/// `/identity` and `/api`. Bitwarden's own cloud splits them across
/// `identity.bitwarden.com` and `api.bitwarden.com`, so pointing the app at
/// `https://vault.bitwarden.com` and appending `/identity` would 404.
struct BitwardenEndpoints: Equatable {
    let identity: URL
    let api: URL
    /// The host TLS exceptions and the account label are scoped to.
    let host: String

    init(serverURL: URL) throws {
        guard let host = serverURL.host, !host.isEmpty else {
            throw VaultSyncError.server(
                "\"\(serverURL.absoluteString)\" has no host. Enter a full URL such as "
                + "https://vault.lan or https://vault.bitwarden.com."
            )
        }
        guard let scheme = serverURL.scheme?.lowercased(), scheme == "https" || scheme == "http" else {
            throw VaultSyncError.server(
                "\"\(serverURL.absoluteString)\" is not an http(s) URL."
            )
        }
        self.host = host

        if host == "bitwarden.com" || host == "vault.bitwarden.com" || host == "www.bitwarden.com" {
            guard let identity = URL(string: "https://identity.bitwarden.com"),
                  let api = URL(string: "https://api.bitwarden.com")
            else {
                throw VaultSyncError.server("Could not build Bitwarden cloud endpoints.")
            }
            self.identity = identity
            self.api = api
        } else {
            // Trailing slashes matter to `appendingPathComponent` only in that
            // they produce "//"; normalise first.
            var base = serverURL
            while base.absoluteString.hasSuffix("/"),
                  let trimmed = URL(string: String(base.absoluteString.dropLast())) {
                base = trimmed
            }
            self.identity = base.appendingPathComponent("identity")
            self.api = base.appendingPathComponent("api")
        }
    }
}

// MARK: - Wire models

/// JSON coding shared by every Bitwarden request and response.
enum BitwardenJSON {
    /// Bitwarden's JSON is not consistently cased and never has been: the OAuth
    /// endpoints answer in `snake_case` (`access_token`), the vault endpoints
    /// answered in `PascalCase` for years and in `camelCase` today, and a
    /// single response can mix both (`access_token` beside `Key`). Rather than
    /// spell three `CodingKeys` variants per model, normalise every incoming
    /// key to camelCase and decode once.
    static func normalisedKey(_ key: String) -> String {
        var joined = key
        if key.contains("_") {
            let parts = key.split(separator: "_", omittingEmptySubsequences: true).map(String.init)
            guard let first = parts.first else { return key }
            joined = first + parts.dropFirst().map { part -> String in
                guard let head = part.first else { return part }
                return head.uppercased() + part.dropFirst()
            }.joined()
        }
        guard let head = joined.first else { return joined }
        return head.lowercased() + joined.dropFirst()
    }

    static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .custom { path in
            BitwardenCodingKey(stringValue: normalisedKey(path[path.count - 1].stringValue))
        }
        return decoder
    }

    static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        // Modern Bitwarden and Vaultwarden both accept camelCase request
        // bodies; Vaultwarden matches field names case-insensitively.
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}

struct BitwardenCodingKey: CodingKey {
    var stringValue: String
    var intValue: Int?

    init(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = Int(stringValue)
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

struct BitwardenPrelogin: Decodable, Equatable {
    var kdf: Int
    var kdfIterations: Int
    var kdfMemory: Int?
    var kdfParallelism: Int?

    /// Turn the server's three loose integers into the KDF we can act on.
    func kdfDescriptor() throws -> BitwardenKDF {
        switch kdf {
        case 0:
            return .pbkdf2(iterations: kdfIterations)
        case 1:
            // The server sends nulls for these on a PBKDF2 account; on an
            // Argon2 account they are always present. Defaults match
            // Bitwarden's own (3 passes, 64 MiB, 4 lanes) so a server that
            // omits them does not produce a nonsense key.
            return .argon2id(
                iterations: kdfIterations,
                memoryMiB: kdfMemory ?? 64,
                parallelism: kdfParallelism ?? 4
            )
        default:
            throw VaultSyncError.server(
                "This account uses KDF type \(kdf), which Ghostty does not know. Only PBKDF2 (0) "
                + "and Argon2id (1) exist today."
            )
        }
    }
}

struct BitwardenTokenResponse: Decodable {
    var accessToken: String
    var expiresIn: Int?
    var refreshToken: String?
    /// The account's protected user key, as an EncString. Present on the
    /// password grant and on the client-credentials grant.
    var key: String?
    var privateKey: String?
    var kdf: Int?
    var kdfIterations: Int?
    var kdfMemory: Int?
    var kdfParallelism: Int?
}

/// The 400 the identity endpoint returns instead of a token.
struct BitwardenTokenError: Decodable {
    var error: String?
    var errorDescription: String?
    var errorModel: ErrorModel?
    /// Modern shape: `{"0": {...}}` keyed by provider number.
    var twoFactorProviders2: [String: AnyCodableIgnored?]?
    /// Legacy shape: `["0"]`.
    var twoFactorProviders: [String]?

    struct ErrorModel: Decodable {
        var message: String?
    }

    /// Anything whose contents we do not care about, only its presence.
    struct AnyCodableIgnored: Decodable {
        init(from decoder: Decoder) throws {}
    }

    var providerIDs: [String] {
        if let twoFactorProviders2, !twoFactorProviders2.isEmpty {
            return twoFactorProviders2.keys.sorted()
        }
        return twoFactorProviders ?? []
    }

    var message: String? {
        errorModel?.message ?? errorDescription ?? error
    }
}

struct BitwardenSyncResponse: Decodable {
    struct Profile: Decodable {
        var id: String?
        var email: String?
        var name: String?
        /// The protected user key, same value the token response carries.
        var key: String?
    }

    var profile: Profile?
    var ciphers: [BitwardenCipher]?
}

/// A cipher as the server reports it.
struct BitwardenCipher: Decodable, Equatable {
    /// Bitwarden's `CipherType`.
    enum Kind: Int {
        case login = 1
        case secureNote = 2
        case card = 3
        case identity = 4
        case sshKey = 5
    }

    struct SSHKey: Codable, Equatable {
        var privateKey: String?
        var publicKey: String?
        var keyFingerprint: String?
    }

    struct SecureNote: Codable, Equatable {
        /// Bitwarden only ever defines 0 ("generic").
        var type: Int?
    }

    var id: String?
    var organizationId: String?
    var folderId: String?
    var type: Int
    var name: String?
    var notes: String?
    var favorite: Bool?
    var reprompt: Int?
    var sshKey: SSHKey?
    var secureNote: SecureNote?
    var revisionDate: String?
    var deletedDate: String?

    var kind: Kind? { Kind(rawValue: type) }
    /// Items in the trash still arrive in `/api/sync`; treat them as gone.
    var isDeleted: Bool { !(deletedDate ?? "").isEmpty }
}

/// A cipher as the server wants it written.
///
/// Separate from `BitwardenCipher` because the request shape genuinely differs:
/// `id`, `object` and `revisionDate` are server-owned and rejected or ignored
/// on the way in, and `lastKnownRevisionDate` exists only on the way in — it is
/// the server's optimistic-concurrency check.
struct BitwardenCipherRequest: Encodable {
    var type: Int
    var name: String
    var notes: String?
    var folderId: String?
    var organizationId: String?
    var favorite: Bool = false
    var reprompt: Int = 0
    var sshKey: BitwardenCipher.SSHKey?
    var secureNote: BitwardenCipher.SecureNote?
    var lastKnownRevisionDate: String?
}

// MARK: - Errors

/// Authentication outcomes the UI has to react to differently, rather than
/// showing the same "login failed" for all of them.
enum BitwardenAuthError: Error, LocalizedError, Equatable {
    /// The server accepted the password and now wants a second factor.
    case twoFactorRequired(providers: [String])
    case invalidCredentials(String)
    case captchaRequired

    var errorDescription: String? {
        switch self {
        case .twoFactorRequired:
            return "This account has two-step login enabled. Enter the six-digit code from your "
                + "authenticator app."
        case .invalidCredentials(let detail):
            return detail.isEmpty
                ? "The email or master password was not accepted."
                : detail
        case .captchaRequired:
            return "The server is asking for a CAPTCHA, which Ghostty cannot show. Sign in once in "
                + "a web browser to clear it, then try again."
        }
    }

    /// TOTP is provider 0. Anything else (Duo, WebAuthn, email) needs a flow
    /// this client does not implement, so say so precisely.
    var supportsTOTP: Bool {
        if case .twoFactorRequired(let providers) = self {
            return providers.isEmpty || providers.contains("0")
        }
        return false
    }
}

// MARK: - Client

/// Bitwarden / Vaultwarden REST client.
///
/// An `actor` because it owns mutable session state (access token, expiry,
/// refresh token) that `push` and `pull` can both reach for concurrently, and
/// a token refresh racing itself produces two sessions and one revoked token.
actor BitwardenAPIClient {
    /// Tokens recovered from the Keychain at launch.
    struct RestoredSession {
        var accessToken: String?
        var accessTokenExpiry: Date?
        var refreshToken: String?
    }

    struct Configuration {
        var serverURL: URL
        /// See `BitwardenTLSDelegate`. Default off, deliberately.
        var allowsSelfSignedCertificates: Bool = false
        /// Stable per-install id. The server ties sessions and two-step
        /// "remember this device" to it, so it must not change per launch.
        var deviceIdentifier: String = UUID().uuidString
        var deviceName: String = "Ghostty iOS"
        /// Bitwarden's `DeviceType`: 1 is iOS.
        var deviceType: Int = 1
        /// The official iOS app sends `mobile`; Vaultwarden does not care, and
        /// `ios` is what this integration was specified against. Exposed so a
        /// server that does validate it can be satisfied without a rebuild.
        var clientID: String = "ios"
        /// Adopted synchronously in `init` rather than through a later
        /// `await`: a cold start that kicks off a pull immediately must not
        /// race the session restore and see an unauthenticated client.
        var restoredSession: RestoredSession?
    }

    private let configuration: Configuration
    private let endpoints: BitwardenEndpoints
    private let transport: BitwardenTransport

    private var accessToken: String?
    private var accessTokenExpiry: Date?
    private var refreshToken: String?

    /// Refresh slightly early; a token that expires mid-flight looks like an
    /// auth failure to the user.
    private let refreshLeeway: TimeInterval = 60

    var host: String { endpoints.host }

    init(configuration: Configuration, transport: BitwardenTransport? = nil) throws {
        // Resolved into a local before any `self` assignment: reading back a
        // stored property of a partially-initialised actor from its own
        // nonisolated `init` is an error in Swift 6.
        let endpoints = try BitwardenEndpoints(serverURL: configuration.serverURL)
        self.configuration = configuration
        self.endpoints = endpoints
        self.transport = transport ?? URLSessionTransport(
            selfSignedHost: configuration.allowsSelfSignedCertificates ? endpoints.host : nil
        )
        self.accessToken = configuration.restoredSession?.accessToken
        self.accessTokenExpiry = configuration.restoredSession?.accessTokenExpiry
        self.refreshToken = configuration.restoredSession?.refreshToken
    }

    // MARK: Session

    func currentRefreshToken() -> String? { refreshToken }
    func currentAccessToken() -> String? { accessToken }
    func currentAccessTokenExpiry() -> Date? { accessTokenExpiry }

    func clearSession() {
        accessToken = nil
        accessTokenExpiry = nil
        refreshToken = nil
    }

    // MARK: Prelogin

    /// Ask the server how this account's master key is derived.
    ///
    /// Unauthenticated by design — the client needs the KDF parameters before
    /// it can produce anything the server would accept.
    func prelogin(email: String) async throws -> BitwardenPrelogin {
        var request = URLRequest(url: endpoints.identity.appendingPathComponent("accounts/prelogin"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try BitwardenJSON.encoder.encode(
            ["email": BitwardenCrypto.normalise(email: email)]
        )

        let (data, response) = try await send(request)
        try throwIfError(data: data, response: response, context: "asking the server for this account's login settings")
        return try decode(BitwardenPrelogin.self, from: data, context: "prelogin")
    }

    // MARK: Tokens

    /// Password grant. `masterPasswordHash` is the base64 hash, never the
    /// password itself — the server never sees the password.
    func login(
        email: String,
        masterPasswordHash: String,
        totp: String?
    ) async throws -> BitwardenTokenResponse {
        var form: [String: String] = [
            "grant_type": "password",
            "username": BitwardenCrypto.normalise(email: email),
            "password": masterPasswordHash,
            "scope": "api offline_access",
            "client_id": configuration.clientID,
            "deviceType": String(configuration.deviceType),
            "deviceIdentifier": configuration.deviceIdentifier,
            "deviceName": configuration.deviceName,
        ]
        if let totp, !totp.trimmingCharacters(in: .whitespaces).isEmpty {
            form["twoFactorToken"] = totp.trimmingCharacters(in: .whitespaces)
            form["twoFactorProvider"] = "0"       // 0 = authenticator app (TOTP)
            form["twoFactorRemember"] = "0"
        }
        return try await token(form: form)
    }

    /// Client-credentials grant, for a personal API key.
    ///
    /// Note there is no refresh token on this grant and no `offline_access`
    /// scope: the API key *is* the long-lived credential, so a fresh token is
    /// one request away.
    func loginWithAPIKey(clientID: String, clientSecret: String) async throws -> BitwardenTokenResponse {
        try await token(form: [
            "grant_type": "client_credentials",
            "client_id": clientID,
            "client_secret": clientSecret,
            "scope": "api",
            "deviceType": String(configuration.deviceType),
            "deviceIdentifier": configuration.deviceIdentifier,
            "deviceName": configuration.deviceName,
        ])
    }

    @discardableResult
    func refreshAccessToken() async throws -> BitwardenTokenResponse {
        guard let refreshToken else {
            throw VaultSyncError.notConnected("Bitwarden")
        }
        return try await token(form: [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": configuration.clientID,
        ])
    }

    private func token(form: [String: String]) async throws -> BitwardenTokenResponse {
        var request = URLRequest(url: endpoints.identity.appendingPathComponent("connect/token"))
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        // Some deployments key rate limits and device trust off these headers
        // rather than off the form fields, so send both.
        request.setValue(String(configuration.deviceType), forHTTPHeaderField: "Device-Type")
        request.httpBody = Data(Self.formURLEncoded(form).utf8)

        let (data, response) = try await send(request)

        if response.statusCode == 400 || response.statusCode == 401 {
            throw Self.authError(from: data, statusCode: response.statusCode)
        }
        try throwIfError(data: data, response: response, context: "signing in")

        let token = try decode(BitwardenTokenResponse.self, from: data, context: "the login response")
        accessToken = token.accessToken
        // Absent `expires_in` means "assume short" rather than "assume forever".
        accessTokenExpiry = Date().addingTimeInterval(TimeInterval(token.expiresIn ?? 3600))
        if let newRefresh = token.refreshToken { refreshToken = newRefresh }
        return token
    }

    private static func authError(from data: Data, statusCode: Int) -> Error {
        guard let parsed = try? BitwardenJSON.decoder.decode(BitwardenTokenError.self, from: data) else {
            return VaultSyncError.server("The server rejected the sign-in (HTTP \(statusCode)).")
        }
        let providers = parsed.providerIDs
        if !providers.isEmpty || parsed.error == "invalid_grant"
            && (parsed.errorDescription?.localizedCaseInsensitiveContains("two") ?? false) {
            return BitwardenAuthError.twoFactorRequired(providers: providers)
        }
        if parsed.message?.localizedCaseInsensitiveContains("captcha") ?? false {
            return BitwardenAuthError.captchaRequired
        }
        return BitwardenAuthError.invalidCredentials(parsed.message ?? "")
    }

    // MARK: Vault

    func sync() async throws -> BitwardenSyncResponse {
        var components = URLComponents(
            url: endpoints.api.appendingPathComponent("sync"),
            resolvingAgainstBaseURL: false
        )
        // Domain equivalence lists are a login-autofill feature; we have no use
        // for them and they are a meaningful share of the response size.
        components?.queryItems = [URLQueryItem(name: "excludeDomains", value: "true")]
        guard let url = components?.url else {
            throw VaultSyncError.server("Could not build the sync URL for \(endpoints.api).")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (data, response) = try await sendAuthorized(request)
        try throwIfError(data: data, response: response, context: "downloading the vault")
        return try decode(BitwardenSyncResponse.self, from: data, context: "the vault sync response")
    }

    @discardableResult
    func createCipher(_ cipher: BitwardenCipherRequest) async throws -> BitwardenCipher {
        var request = URLRequest(url: endpoints.api.appendingPathComponent("ciphers"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try BitwardenJSON.encoder.encode(cipher)

        let (data, response) = try await sendAuthorized(request)
        try throwIfError(data: data, response: response, context: "saving an item to the vault")
        return try decode(BitwardenCipher.self, from: data, context: "the created item")
    }

    @discardableResult
    func updateCipher(id: String, _ cipher: BitwardenCipherRequest) async throws -> BitwardenCipher {
        var request = URLRequest(url: endpoints.api.appendingPathComponent("ciphers/\(id)"))
        request.httpMethod = "PUT"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try BitwardenJSON.encoder.encode(cipher)

        let (data, response) = try await sendAuthorized(request)
        try throwIfError(data: data, response: response, context: "updating an item in the vault")
        return try decode(BitwardenCipher.self, from: data, context: "the updated item")
    }

    func deleteCipher(id: String) async throws {
        var request = URLRequest(url: endpoints.api.appendingPathComponent("ciphers/\(id)"))
        request.httpMethod = "DELETE"
        let (data, response) = try await sendAuthorized(request)
        // A 404 means the item is already gone, which is the state we wanted.
        guard response.statusCode != 404 else { return }
        try throwIfError(data: data, response: response, context: "deleting an item from the vault")
    }

    // MARK: Plumbing

    private func sendAuthorized(_ request: URLRequest) async throws -> (data: Data, response: HTTPURLResponse) {
        try await refreshIfExpired()

        var authorized = request
        guard let accessToken else { throw VaultSyncError.notConnected("Bitwarden") }
        authorized.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        authorized.setValue("application/json", forHTTPHeaderField: "Accept")

        let result = try await send(authorized)
        guard result.response.statusCode == 401, refreshToken != nil else { return result }

        // The server can revoke a token before it expires (password change,
        // session wipe). One refresh-and-retry, then give up rather than loop.
        try await refreshAccessToken()
        guard let renewed = self.accessToken else { throw VaultSyncError.notConnected("Bitwarden") }
        var retry = request
        retry.setValue("Bearer \(renewed)", forHTTPHeaderField: "Authorization")
        retry.setValue("application/json", forHTTPHeaderField: "Accept")
        return try await send(retry)
    }

    private func refreshIfExpired() async throws {
        guard let expiry = accessTokenExpiry else { return }
        guard Date().addingTimeInterval(refreshLeeway) >= expiry else { return }
        guard refreshToken != nil else { return }
        try await refreshAccessToken()
    }

    private func send(_ request: URLRequest) async throws -> (data: Data, response: HTTPURLResponse) {
        do {
            return try await transport.send(request)
        } catch let error as VaultSyncError {
            throw error
        } catch let error as URLError where error.code == .cancelled {
            throw VaultSyncError.cancelled
        } catch let error as URLError where error.code == .serverCertificateUntrusted
            || error.code == .serverCertificateHasUnknownRoot
            || error.code == .serverCertificateNotYetValid
            || error.code == .serverCertificateHasBadDate {
            throw VaultSyncError.server(
                "\(endpoints.host) presented a certificate iOS does not trust. If this is your own "
                + "server, turn on \"Trust this server's certificate\" for it, or install its "
                + "certificate authority on this device."
            )
        } catch {
            throw VaultSyncError.server(
                "Could not reach \(endpoints.host): \(error.localizedDescription)"
            )
        }
    }

    private func throwIfError(data: Data, response: HTTPURLResponse, context: String) throws {
        guard !(200..<300).contains(response.statusCode) else { return }

        var detail = "HTTP \(response.statusCode)"
        if let parsed = try? BitwardenJSON.decoder.decode(BitwardenTokenError.self, from: data),
           let message = parsed.message, !message.isEmpty {
            detail = message
        } else if let body = String(data: data.prefix(400), encoding: .utf8),
                  !body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            detail = "HTTP \(response.statusCode): \(body)"
        }
        throw VaultSyncError.server("The server refused while \(context) — \(detail)")
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data, context: String) throws -> T {
        do {
            return try BitwardenJSON.decoder.decode(type, from: data)
        } catch {
            throw VaultSyncError.badResponse(
                "Could not read \(context). \(error.localizedDescription)"
            )
        }
    }

    /// `application/x-www-form-urlencoded`, with `+` and `&` and `=` escaped.
    ///
    /// `.urlQueryAllowed` leaves `+` alone, and a `+` in a form body decodes as
    /// a space — which silently corrupts base64 master password hashes, where
    /// `+` is one of the 64 characters.
    static func formURLEncoded(_ fields: [String: String]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return fields
            .sorted { $0.key < $1.key }
            .map { key, value in
                let k = key.addingPercentEncoding(withAllowedCharacters: allowed) ?? key
                let v = value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
                return "\(k)=\(v)"
            }
            .joined(separator: "&")
    }
}
