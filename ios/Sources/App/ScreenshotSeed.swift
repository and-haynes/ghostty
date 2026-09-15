import Foundation

/// Debug-only launch-argument seeding.
///
/// The UI tests that produce the screenshots in docs/ need a vault with
/// something in it, and they must exercise the *real* code paths — a fake
/// identity drawn on screen would prove nothing. Passing `-ghostty-seed`
/// generates a genuine ed25519 key through `Vault.generateIdentity` and adds
/// sample hosts. It is compiled out of release builds entirely.
enum ScreenshotSeed {
    static var isRequested: Bool {
        #if DEBUG
        return ProcessInfo.processInfo.arguments.contains("-ghostty-seed")
        #else
        return false
        #endif
    }

    @MainActor
    static func apply(to vault: Vault) {
        #if DEBUG
        guard isRequested else { return }

        // Idempotent and self-healing. The app's container survives between
        // test runs, so a seed that bailed out on "hosts already exist" left
        // whatever half-state the previous run produced — including hosts
        // pointing at an identity that failed to generate. Rebuilding the
        // sample hosts every time is cheap and always coherent.
        var identity = vault.identities.first { $0.name == seedIdentityName }
        if identity == nil {
            do {
                identity = try vault.generateIdentity(name: seedIdentityName, type: .ed25519)
            } catch {
                // Surfaced rather than swallowed: when this fails it is almost
                // always a Keychain entitlement problem, and a silent empty key
                // list is a miserable thing to debug.
                NSLog("ghostty: seed key generation failed: \(error)")
            }
        }

        for sample in samples(identityID: identity?.id) {
            if let existing = vault.hosts.first(where: { $0.alias == sample.alias }) {
                vault.deleteHost(existing)
            }
            vault.upsert(sample)
        }
        #endif
    }

    private static let seedIdentityName = "iPhone"

    private static func samples(identityID: UUID?) -> [Host] {
        [
            Host(
                alias: "noether",
                hostname: "10.0.0.81",
                username: "andy",
                identityID: identityID,
                group: "homelab",
                tags: ["linux", "workspace"],
                colorHex: "#4CE066",
                notes: "agent workspace"
            ),
            Host(
                alias: "git.lan",
                hostname: "git.lan",
                username: "git",
                identityID: identityID,
                group: "homelab",
                tags: ["forgejo"],
                colorHex: "#89B4FA"
            ),
            Host(
                alias: "pi-a",
                hostname: "10.0.0.41",
                username: "andy",
                identityID: identityID,
                group: "homelab",
                tags: ["pi", "gateway"],
                colorHex: "#F9E2AF"
            ),
            Host(
                alias: "sagan",
                hostname: "10.0.0.45",
                username: "andy",
                usesPassword: true,
                group: "macs",
                tags: ["mac", "builds"],
                colorHex: "#F5C2E7"
            ),
        ]
    }
}
