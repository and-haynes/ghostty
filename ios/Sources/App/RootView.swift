import SwiftUI

struct RootView: View {
    @EnvironmentObject private var vault: Vault
    @EnvironmentObject private var settings: AppSettings
    @EnvironmentObject private var sessions: SessionManager

    @State private var selection: Tab = .hosts

    enum Tab: Hashable {
        case hosts, sessions, identities, settings
    }

    var body: some View {
        TabView(selection: $selection) {
            HostsView(onConnected: { selection = .sessions })
                .tabItem { Label("Hosts", systemImage: "server.rack") }
                .tag(Tab.hosts)

            SessionsView()
                .tabItem { Label("Sessions", systemImage: "terminal") }
                .badge(sessions.sessions.count)
                .tag(Tab.sessions)

            IdentitiesView()
                .tabItem { Label("Keys", systemImage: "key.fill") }
                .tag(Tab.identities)

            SettingsView(onOpenDemo: {
                sessions.openDemo(settings: settings)
                selection = .sessions
            })
            .tabItem { Label("Settings", systemImage: "gearshape") }
            .tag(Tab.settings)
        }
        .onAppear {
            sessions.configure(vault: vault, settings: settings)
        }
    }
}
