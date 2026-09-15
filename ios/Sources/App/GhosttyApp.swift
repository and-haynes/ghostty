import SwiftUI

@main
struct GhosttyApp: App {
    @StateObject private var vault = Vault()
    @StateObject private var settings = AppSettings()
    @StateObject private var sessions = SessionManager()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(vault)
                .environmentObject(settings)
                .environmentObject(sessions)
                .preferredColorScheme(.dark)
        }
    }
}
