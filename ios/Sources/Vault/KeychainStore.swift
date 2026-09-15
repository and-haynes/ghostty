import Foundation
import Security

/// How a secret may be read back.
enum KeychainAccessibility: Sendable {
    /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — never leaves this device.
    case whenUnlockedThisDeviceOnly
    /// `kSecAttrAccessibleWhenUnlocked` — eligible for iCloud Keychain sync.
    case whenUnlocked

    var secAttr: CFString {
        switch self {
        case .whenUnlockedThisDeviceOnly: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .whenUnlocked: return kSecAttrAccessibleWhenUnlocked
        }
    }
}

struct KeychainItemOptions: Sendable {
    var accessibility: KeychainAccessibility = .whenUnlockedThisDeviceOnly
    /// Gate reads behind `.biometryCurrentSet` (Face ID / Touch ID).
    var requiresBiometrics: Bool = false
    /// Mark `kSecAttrSynchronizable` so iCloud Keychain replicates the item.
    /// Mutually exclusive with `whenUnlockedThisDeviceOnly` and with biometrics.
    var synchronizable: Bool = false

    static let deviceOnly = KeychainItemOptions()
}

enum KeychainError: Error, LocalizedError, Equatable {
    case unexpectedStatus(OSStatus)
    case accessControlFailed
    case userCancelled

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status):
            let msg = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
            return "Keychain error \(status): \(msg)"
        case .accessControlFailed:
            return "Could not build a Keychain access control policy."
        case .userCancelled:
            return "Authentication was cancelled."
        }
    }
}

/// The vault's only door to secret material. Abstracted so unit tests can
/// swap in `InMemoryKeychain` — the simulator's Keychain is available but a
/// test that writes to it leaks state between runs, and Secure Enclave and
/// biometry are not testable there at all.
protocol KeychainStore: AnyObject {
    func set(_ data: Data, account: String, options: KeychainItemOptions) throws
    func get(account: String, prompt: String?) throws -> Data?
    func delete(account: String) throws
    func accounts(withPrefix prefix: String) throws -> [String]
}
