import Foundation

/// A `KeychainStore` that lives in a dictionary.
///
/// Used by unit tests and by `Vault.preview()`. It also records the
/// `KeychainItemOptions` each secret was written with, so a test can assert
/// that the vault asked for device-only storage or biometric gating — the
/// protections are the part most likely to regress silently, because a secret
/// stored with the wrong accessibility still reads back fine.
final class InMemoryKeychain: KeychainStore {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    private var options: [String: KeychainItemOptions] = [:]

    /// Make the next `get` behave as if the user dismissed the Face ID sheet.
    var simulateUserCancel = false

    init() {}

    func set(_ data: Data, account: String, options itemOptions: KeychainItemOptions) throws {
        lock.lock()
        defer { lock.unlock() }
        items[account] = data
        options[account] = itemOptions
    }

    func get(account: String, prompt: String?) throws -> Data? {
        if simulateUserCancel { throw KeychainError.userCancelled }
        lock.lock()
        defer { lock.unlock() }
        return items[account]
    }

    func delete(account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        items.removeValue(forKey: account)
        options.removeValue(forKey: account)
    }

    func accounts(withPrefix prefix: String) throws -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return items.keys.filter { $0.hasPrefix(prefix) }.sorted()
    }

    // MARK: - Test introspection

    /// The options a secret was stored with, or nil if no such secret exists.
    var storedOptions: [String: KeychainItemOptions] {
        lock.lock()
        defer { lock.unlock() }
        return options
    }

    func contains(account: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return items[account] != nil
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return items.count
    }
}
