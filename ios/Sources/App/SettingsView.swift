import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var settings: AppSettings
    @EnvironmentObject private var vault: Vault
    @EnvironmentObject private var sync: VaultSyncEngine
    @ObservedObject private var haptics = Haptics.shared

    var body: some View {
        NavigationStack {
            Form {
                Section("Terminal") {
                    HStack {
                        Text("Font size")
                        Spacer()
                        Text("\(Int(settings.fontSize)) pt").foregroundStyle(.secondary)
                    }
                    Slider(value: $settings.fontSize, in: 8...24, step: 1)
                    Picker("Theme", selection: $settings.themeName) {
                        ForEach(TerminalTheme.all) { theme in
                            Text(theme.name).tag(theme.name)
                        }
                    }
                    ThemePreview(theme: settings.theme)
                }

                Section {
                    LabeledField("Default TERM", text: $settings.defaultTerm, placeholder: "xterm-256color", autocorrect: false)
                } header: {
                    Text("Compatibility")
                } footer: {
                    Text("Sent in the pty-req. xterm-256color is the safe default because remote hosts do not ship ghostty's terminfo.")
                }

                Section {
                    Toggle("Key bar above keyboard", isOn: $settings.keyBarEnabled)
                    Toggle("Confirm risky pastes", isOn: $settings.confirmUnsafePaste)
                    Picker("Haptics", selection: $haptics.level) {
                        ForEach(HapticLevel.allCases) { level in
                            Text(level.title).tag(level)
                        }
                    }
                    Text(haptics.level.detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("Input")
                } footer: {
                    Text("A paste containing a line break runs the command as soon as it lands; the confirmation is the only thing between a mis-tap and a command you did not mean to run.")
                }

                Section {
                    ForEach(VaultSyncProviderKind.allCases) { kind in
                        NavigationLink {
                            SyncProviderView(kind: kind)
                        } label: {
                            SyncProviderRow(kind: kind, status: sync.status(kind), busy: sync.isBusy(kind))
                        }
                    }
                    if !sync.connectedKinds.isEmpty {
                        Button("Sync all now", systemImage: "arrow.triangle.2.circlepath") {
                            Task { await sync.syncAllConnected() }
                        }
                    }
                } header: {
                    Text("Sync")
                } footer: {
                    Text("Providers hold a copy of hosts, pinned host keys and exportable private keys. Conflicts resolve newest-wins. Secure Enclave keys never leave this device and are marked device-only wherever they appear.")
                }

                Section {
                    Toggle("Sync new keys via iCloud Keychain", isOn: $settings.iCloudSyncDefault)
                } header: {
                    Text("Vault")
                } footer: {
                    Text("Off by default. Private keys are otherwise stored accessible-when-unlocked, this device only. Secure Enclave and biometry-protected keys can never sync, whatever this is set to.")
                }

                Section {
                    NavigationLink("Known hosts (\(vault.knownHosts.count))") { KnownHostsView() }
                } header: {
                    Text("Diagnostics")
                } footer: {
                    Text("The Console tab runs libghostty-vt against the app's own command interpreter — no network, no credentials. It is where the renderer and key bar can be exercised without a server.")
                }

                Section("About") {
                    LabeledContent("Terminal core", value: "libghostty-vt")
                    LabeledContent("Transport", value: "swift-nio-ssh")
                    LabeledContent("Version", value: Bundle.main.appVersion)
                }
            }
            .navigationTitle("Settings")
        }
    }
}

private struct ThemePreview: View {
    let theme: TerminalTheme

    var body: some View {
        HStack(spacing: 3) {
            ForEach(Array(theme.ansi.prefix(16).enumerated()), id: \.offset) { _, color in
                RoundedRectangle(cornerRadius: 2)
                    .fill(Color(color.cgColor))
                    .frame(height: 18)
            }
        }
        .padding(6)
        .background(Color(theme.background.cgColor), in: RoundedRectangle(cornerRadius: 6))
    }
}

extension Bundle {
    var appVersion: String {
        let short = infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        let build = infoDictionary?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }
}
