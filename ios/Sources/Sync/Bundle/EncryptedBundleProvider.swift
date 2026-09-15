import Foundation

/// Vault sync by moving one encrypted file around yourself.
///
/// Every other provider talks to something. This one deliberately does not:
/// it writes a `.ghosttyvault` file into Documents and hands the URL to the
/// UI for a share sheet, and it reads one back that the user picked in Files.
/// That makes it the answer for every password manager whose only integration
/// story is "export a CSV" — KeePass, Proton Pass, Enpass, a USB stick.
///
/// The provider holds no server, no account and no session. The single piece
/// of state worth protecting is the passphrase, and it lives in the Keychain.
@MainActor
final class EncryptedBundleProvider: VaultSyncProvider {
    let kind: VaultSyncProviderKind = .encryptedBundle

    var helpText: String {
        "For password managers with no usable API — KeePass, Proton Pass, "
            + "anything you sync yourself. Export writes one encrypted file you "
            + "move wherever you like; import reads it back on the other device. "
            + "The file is only as safe as its passphrase: anyone who has both "
            + "has your keys, so pick a long one and don't store it beside the file."
    }

    var status: VaultSyncStatus

    /// The last file `push` wrote, for the UI to hand to a share sheet.
    /// Nil until an export has happened in this launch.
    private(set) var lastExportedFileURL: URL?

    /// Set by the UI after the Files picker returns; consumed by `pull`.
    /// Nil means "nothing to import", which `pull` reports as nil rather than
    /// as an error — a sync run with no file pending is not a failure.
    var pendingImportFileURL: URL?

    /// Shortest passphrase we will accept.
    ///
    /// The bundle's entire security is this string — there is no server to rate
    /// limit guesses and no second factor, and the file may sit in someone
    /// else's cloud storage. 600 000 PBKDF2 iterations buys roughly 20 bits
    /// against an offline attacker, which is not enough to rescue "hunter2".
    static let minimumPassphraseLength = 8

    private let keychain: KeychainStore
    private let directory: URL
    private let passphraseAccount = "sync.bundle.passphrase"

    /// Cached for the session so a push/pull pair doesn't hit the Keychain
    /// twice; the Keychain copy is the source of truth across launches.
    private var cachedPassphrase: String?

    init(keychain: KeychainStore = SystemKeychain(), directory: URL? = nil) {
        self.keychain = keychain
        self.directory = directory ?? Self.defaultDirectory()
        self.status = VaultSyncStatus()
        // A passphrase stored on a previous launch means the user already set
        // this provider up; reflect that instead of making them re-enter it.
        // `try?` already flattens the optional the getter returns, so one
        // binding is enough here.
        if let stored = try? keychain.get(account: passphraseAccount, prompt: nil),
           let text = String(data: stored, encoding: .utf8),
           !text.isEmpty
        {
            cachedPassphrase = text
            status.isConnected = true
            status.accountLabel = Self.accountLabel
        }
    }

    private static let accountLabel = "This device · Files"

    private static func defaultDirectory() -> URL {
        let fm = FileManager.default
        // Documents, not Application Support: the point of the file is that the
        // user can reach it, and only Documents shows up in the Files app when
        // the app declares UIFileSharingEnabled.
        return (try? fm.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true))
            ?? fm.temporaryDirectory
    }

    // MARK: - Connect / disconnect

    func connect(_ credentials: VaultSyncCredentials) async throws {
        guard case .bundlePassphrase(let passphrase) = credentials else {
            throw VaultSyncError.unsupportedCredentials(
                "An encrypted bundle needs a passphrase, not an account."
            )
        }
        guard !passphrase.isEmpty else {
            throw VaultSyncError.unsupportedCredentials(
                "A bundle needs a passphrase. It is the only thing protecting the keys inside it."
            )
        }
        guard passphrase.count >= Self.minimumPassphraseLength else {
            throw VaultSyncError.unsupportedCredentials(
                "That passphrase is too short. Use at least \(Self.minimumPassphraseLength) characters — "
                    + "a bundle can be attacked offline for as long as somebody likes."
            )
        }

        do {
            // Device-only: the passphrase is the one thing that must not travel
            // alongside the file, and iCloud Keychain would put it on the same
            // devices the bundle is likely to land on.
            try keychain.set(Data(passphrase.utf8), account: passphraseAccount, options: .deviceOnly)
        } catch {
            throw VaultSyncError.crypto("Couldn't store the passphrase: \(error.localizedDescription)")
        }

        cachedPassphrase = passphrase
        status.isConnected = true
        status.accountLabel = Self.accountLabel
        status.lastResult = "Ready to export."
        status.lastResultWasError = false
    }

    func disconnect() async {
        cachedPassphrase = nil
        pendingImportFileURL = nil
        try? keychain.delete(account: passphraseAccount)
        // Deliberately leaves any exported file in place: it is the user's
        // file, possibly their only backup, and forgetting the passphrase in
        // the app is not a reason to destroy it.
        status = VaultSyncStatus()
    }

    // MARK: - Export

    func push(_ snapshot: VaultSnapshot) async throws {
        let passphrase = try currentPassphrase()
        let data = try EncryptedBundle.export(snapshot, passphrase: passphrase)
        let url = directory.appendingPathComponent(Self.fileName(for: Date()))

        do {
            // Complete protection: the bundle is encrypted already, but there
            // is no reason for a locked, stolen phone to give up even the
            // ciphertext.
            try data.write(to: url, options: [.atomic, .completeFileProtection])
        } catch {
            throw VaultSyncError.crypto(
                "Couldn't write the bundle to \(url.lastPathComponent): \(error.localizedDescription)"
            )
        }

        lastExportedFileURL = url
        status.lastSync = Date()
        status.lastResultWasError = false
        status.lastResult = "Exported \(snapshot.summary) to \(url.lastPathComponent). "
            + "Move it somewhere safe — the file is only as strong as its passphrase."
    }

    /// `Ghostty-vault-2026-09-15T143012Z.ghosttyvault`
    ///
    /// ISO-8601 basic format for the time part: colons are legal on APFS but
    /// several places that will touch this file — a share-sheet target, a
    /// Windows machine, a ZIP — are not so relaxed. Second resolution also
    /// means two exports in one session never collide.
    static func fileName(for date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withFullDate, .withTime, .withTimeZone]
        return "Ghostty-vault-\(formatter.string(from: date)).\(EncryptedBundle.fileExtension)"
    }

    // MARK: - Import

    func pull() async throws -> VaultSnapshot? {
        // Nothing queued is the normal state, not a failure: the engine pulls
        // on every sync and this provider only has something to say when the
        // user has just picked a file.
        guard let url = pendingImportFileURL else { return nil }
        let passphrase = try currentPassphrase()

        // A URL from UIDocumentPicker points outside the sandbox and only
        // opens while its security scope is held. Files inside our own
        // Documents return false here, which is not an error.
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw VaultSyncError.badResponse(
                "Couldn't read \(url.lastPathComponent): \(error.localizedDescription)"
            )
        }

        let snapshot: VaultSnapshot
        do {
            snapshot = try EncryptedBundle.import(data, passphrase: passphrase)
        } catch {
            // Clear the pending file on a bad passphrase too: leaving it armed
            // means the next background sync silently retries and fails again.
            pendingImportFileURL = nil
            status.lastResultWasError = true
            status.lastResult = error.localizedDescription
            throw error
        }

        pendingImportFileURL = nil
        status.lastSync = Date()
        status.lastResultWasError = false
        status.lastResult = "Imported \(snapshot.summary) from \(url.lastPathComponent)."
        return snapshot
    }

    // MARK: - Passphrase

    private func currentPassphrase() throws -> String {
        if let cachedPassphrase, !cachedPassphrase.isEmpty { return cachedPassphrase }

        let stored: Data?
        do {
            stored = try keychain.get(account: passphraseAccount, prompt: nil)
        } catch {
            throw VaultSyncError.crypto("Couldn't read the passphrase: \(error.localizedDescription)")
        }
        guard let stored, let text = String(data: stored, encoding: .utf8), !text.isEmpty else {
            throw VaultSyncError.notConnected(displayName)
        }
        cachedPassphrase = text
        return text
    }
}
