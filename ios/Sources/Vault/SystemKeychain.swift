import Foundation
import LocalAuthentication
import Security

/// `KeychainStore` backed by the real iOS Keychain.
///
/// Every item is a `kSecClassGenericPassword` keyed by (service, account).
/// The vault stores private key material and host passwords here; the JSON
/// metadata files in Application Support never contain a secret.
final class SystemKeychain: KeychainStore {
    private let service: String

    init(service: String = "com.morton.ghostty") {
        self.service = service
    }

    // MARK: - Write

    func set(_ data: Data, account: String, options: KeychainItemOptions) throws {
        // SecItemAdd fails with errSecDuplicateItem rather than replacing, and
        // SecItemUpdate cannot change kSecAttrAccessible/AccessControl on an
        // existing item. Delete-then-add is the only way to make "save this
        // secret with these protections" idempotent.
        try deleteIgnoringMissing(account: account)

        var query = baseQuery(account: account)
        query[kSecValueData as String] = data

        if options.requiresBiometrics {
            // A biometry-gated item carries a SecAccessControl *instead of*
            // kSecAttrAccessible — setting both is an errSecParam.
            var error: Unmanaged<CFError>?
            let control = SecAccessControlCreateWithFlags(
                nil,
                options.accessibility.secAttr,
                .biometryCurrentSet,
                &error
            )
            if let error { error.release() }
            guard let control else { throw KeychainError.accessControlFailed }
            query[kSecAttrAccessControl as String] = control
            // Biometric items are device-bound by construction: iCloud
            // Keychain cannot replicate a policy tied to this device's
            // enrolled biometrics, and asking it to just fails the add.
        } else {
            if options.synchronizable {
                // ...ThisDeviceOnly and kSecAttrSynchronizable are mutually
                // exclusive; the caller asked for sync, so widen the class.
                query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
                query[kSecAttrSynchronizable as String] = true
            } else {
                query[kSecAttrAccessible as String] = options.accessibility.secAttr
            }
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
    }

    // MARK: - Read

    func get(account: String, prompt: String?) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        // Without ...SynchronizableAny a lookup only sees local items, so a
        // key the user opted into iCloud Keychain for would read back as
        // missing on the device that created it.
        query[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
        if let prompt, !prompt.isEmpty {
            // kSecUseOperationPrompt is deprecated; an LAContext carries the
            // same reason string and additionally lets a future caller reuse
            // one authentication across several reads.
            let context = LAContext()
            context.localizedReason = prompt
            query[kSecUseAuthenticationContext as String] = context
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound:
            return nil
        case errSecUserCanceled, errSecAuthFailed:
            // The user dismissed Face ID or failed it. This is a normal
            // outcome, not an error worth a scary alert.
            throw KeychainError.userCancelled
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }

    // MARK: - Delete

    func delete(account: String) throws {
        try deleteIgnoringMissing(account: account)
    }

    private func deleteIgnoringMissing(account: String) throws {
        var query = baseQuery(account: account)
        query[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
        let status = SecItemDelete(query as CFDictionary)
        // Deleting something that is not there is the state the caller wanted.
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    // MARK: - Enumeration

    func accounts(withPrefix prefix: String) throws -> [String] {
        var query = baseQuery(account: nil)
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnAttributes as String] = true
        query[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
        guard let items = result as? [[String: Any]] else { return [] }

        return items
            .compactMap { $0[kSecAttrAccount as String] as? String }
            .filter { $0.hasPrefix(prefix) }
            .sorted()
    }

    // MARK: - Query scaffolding

    private func baseQuery(account: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        if let account { query[kSecAttrAccount as String] = account }
        return query
    }
}
