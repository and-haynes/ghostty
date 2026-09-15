import SwiftUI

struct SessionsView: View {
    @EnvironmentObject private var sessions: SessionManager
    @EnvironmentObject private var settings: AppSettings
    @EnvironmentObject private var vault: Vault

    var body: some View {
        NavigationStack {
            Group {
                if sessions.sessions.isEmpty {
                    ContentUnavailableView {
                        Label("No sessions", systemImage: "terminal")
                    } description: {
                        Text("Connect to a host, or open the demo terminal to see the emulator running locally.")
                    } actions: {
                        Button("Open demo terminal") { sessions.openDemo(settings: settings) }
                            .buttonStyle(.borderedProminent)
                    }
                } else {
                    sessionList
                }
            }
            .navigationTitle("Sessions")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button("Open demo terminal", systemImage: "wrench.and.screwdriver") {
                            sessions.openDemo(settings: settings)
                        }
                        if !sessions.sessions.isEmpty {
                            Button("Close all", systemImage: "xmark.circle", role: .destructive) {
                                sessions.closeAll()
                            }
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .accessibilityLabel("Session actions")
                }
            }
            .hostKeyPrompt()
        }
    }

    private var sessionList: some View {
        List {
            ForEach(sessions.sessions) { session in
                NavigationLink {
                    TerminalScreen(session: session)
                } label: {
                    SessionRow(session: session)
                }
                .swipeActions(edge: .trailing) {
                    Button(role: .destructive) { sessions.close(session) } label: {
                        Label("Close", systemImage: "xmark")
                    }
                }
            }
        }
    }
}

private struct SessionRow: View {
    @ObservedObject var session: TerminalSession

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(session.isError ? Color.red : (session.isConnected ? Color.green : Color.orange))
                .frame(width: 9, height: 9)
            VStack(alignment: .leading, spacing: 2) {
                Text(session.title).font(.body.weight(.medium)).lineLimit(1)
                Text(session.statusLabel)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text("\(session.cols)×\(session.rows)")
                .font(.caption2.monospaced())
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - TOFU alert

/// The trust-on-first-use prompt, attached wherever a connection can start.
private struct HostKeyPromptModifier: ViewModifier {
    @EnvironmentObject private var sessions: SessionManager

    func body(content: Content) -> some View {
        content.alert(
            "Unknown host key",
            isPresented: .init(
                get: { sessions.hostKeyPrompt != nil },
                set: { if !$0 { sessions.hostKeyPrompt = nil } }
            ),
            presenting: sessions.hostKeyPrompt
        ) { request in
            Button("Cancel", role: .cancel) { request.respond(false) }
            // Pinning happens in the SSH layer, which is the only place that
            // holds the full key blob; this alert's whole job is to get a
            // human to look at the fingerprint before that happens.
            Button("Trust and connect") { request.respond(true) }
        } message: { request in
            Text("""
            \(request.hostname):\(request.port) has never been connected to before.

            \(request.keyType)
            \(request.fingerprint)

            Check this fingerprint against the server (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) before trusting it.
            """)
        }
    }
}

/// The interactive password prompt.
private struct PasswordPromptModifier: ViewModifier {
    @EnvironmentObject private var sessions: SessionManager
    @State private var password = ""

    func body(content: Content) -> some View {
        content.alert(
            "Password required",
            isPresented: .init(
                get: { sessions.passwordPrompt != nil },
                set: { if !$0 { sessions.passwordPrompt = nil } }
            ),
            presenting: sessions.passwordPrompt
        ) { request in
            SecureField("Password", text: $password)
            Button("Cancel", role: .cancel) {
                request.respond(nil)
                password = ""
            }
            Button("Connect") {
                request.respond(password)
                password = ""
            }
        } message: { request in
            Text("\(request.host.username)@\(request.host.destination) has no key and no saved password.")
        }
    }
}

extension View {
    func hostKeyPrompt() -> some View {
        modifier(HostKeyPromptModifier()).modifier(PasswordPromptModifier())
    }
}
