import SwiftUI

/// The Console tab: a terminal that is always there.
///
/// iOS has no shell, so this is the app's own command line rather than one.
/// It exists as a permanent tab because it is the fastest route to a machine
/// that *does* have a shell — `ssh user@host` and you are connected — and
/// because it gives the terminal, the renderer and the key bar somewhere to be
/// exercised with no network and no credentials.
struct ConsoleView: View {
    @EnvironmentObject private var sessions: SessionManager
    @EnvironmentObject private var settings: AppSettings

    var body: some View {
        NavigationStack {
            Group {
                if let console = sessions.console {
                    TerminalScreen(session: console)
                } else {
                    ContentUnavailableView(
                        "Console unavailable",
                        systemImage: "exclamationmark.triangle",
                        description: Text(sessions.lastError ?? "The terminal could not be created.")
                    )
                }
            }
            .navigationTitle("Console")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button("Clear", systemImage: "eraser") { run("clear") }
                        Button("Help", systemImage: "questionmark.circle") { run("help") }
                        Button("Hosts", systemImage: "server.rack") { run("hosts") }
                        Button("Keys", systemImage: "key") { run("keys") }
                        Button("Colour demo", systemImage: "paintpalette") { run("demo") }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .accessibilityLabel("Console commands")
                }
            }
            .hostKeyPrompt()
        }
        .onAppear { sessions.ensureConsole() }
    }

    /// Feed a command in as if it had been typed, so the transcript reads the
    /// same whether it came from the menu or the keyboard.
    private func run(_ command: String) {
        guard let console = sessions.console else { return }
        console.sendRaw(Data((command + "\r").utf8))
    }
}
