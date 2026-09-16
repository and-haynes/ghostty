import SwiftUI

struct RootView: View {
    @EnvironmentObject private var vault: Vault
    @EnvironmentObject private var settings: AppSettings
    @EnvironmentObject private var sessions: SessionManager

    @State private var selection: Tab = .hosts

    enum Tab: Hashable {
        case hosts, sessions, console, identities, settings
    }

    var body: some View {
        TabView(selection: $selection) {
            HostsView()
                .tabItem { Label("Hosts", systemImage: "server.rack") }
                .tag(Tab.hosts)

            SessionsView()
                .tabItem { Label("Sessions", systemImage: "rectangle.stack") }
                .badge(sessions.sessions.count)
                .tag(Tab.sessions)

            ConsoleView()
                .tabItem { Label("Console", systemImage: "terminal") }
                .tag(Tab.console)

            IdentitiesView()
                .tabItem { Label("Keys", systemImage: "key.fill") }
                .tag(Tab.identities)

            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(Tab.settings)
        }
        .onAppear {
            sessions.configure(vault: vault, settings: settings)
            ScreenshotSeed.apply(to: vault, settings: settings)
        }
        // Connecting — from the hosts list or from `ssh` in the console —
        // should put you where the session is, not leave you looking at the
        // list wondering whether anything happened.
        .onChange(of: sessions.sessionsTabRequest) { _, _ in
            Haptics.shared.fire(.tabSwitch)
            selection = .sessions
        }
        .onChange(of: selection) { _, _ in
            Haptics.shared.fire(.tabSwitch)
        }
    }
}
