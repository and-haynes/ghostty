import SwiftUI

@main
struct GhosttyApp: App {
    @StateObject private var vault: Vault
    @StateObject private var settings = AppSettings()
    @StateObject private var sessions = SessionManager()
    @StateObject private var sync: VaultSyncEngine

    init() {
        // The sync engine holds the vault unowned, so both have to be built
        // here rather than each in its own @StateObject default.
        let vault = Vault()
        _vault = StateObject(wrappedValue: vault)
        _sync = StateObject(wrappedValue: VaultSyncEngine(vault: vault))
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(vault)
                .environmentObject(settings)
                .environmentObject(sessions)
                .environmentObject(sync)
                .environmentObject(Haptics.shared)
                .preferredColorScheme(.dark)
        }
    }
}
