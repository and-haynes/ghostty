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
                    NavigationLink {
                        TrustedAuthoritiesView()
                    } label: {
                        LabeledContent("SSH certificates") {
                            Text(authoritySummary).foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("Certificates")
                } footer: {
                    Text("A certificate authority you name here can vouch for a host, the way an @cert-authority line does in known_hosts — no first-use prompt, no pinned key to re-approve when the host is rebuilt. Ghostty only asks servers for a certificate once there is a CA to check one against.")
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

    private var authoritySummary: String {
        let authorities = settings.trustedAuthorities
        let valid = authorities.keys.count
        let unreadable = authorities.entries.count - valid
        if valid == 0 {
            return unreadable > 0 ? "None readable" : "None"
        }
        let base = valid == 1 ? "1 CA" : "\(valid) CAs"
        return unreadable > 0 ? "\(base), \(unreadable) unreadable" : base
    }
}

/// The trusted certificate authority list.
///
/// One public key per line, as it appears in the CA's `.pub` file — the same
/// text you would put after `@cert-authority *` in `known_hosts`. Lines are
/// parsed as they are typed and shown back with a fingerprint, because a CA
/// entered with a missing character would otherwise fail silently, at connect
/// time, as "no host key algorithm in common".
struct TrustedAuthoritiesView: View {
    @EnvironmentObject private var settings: AppSettings

    var body: some View {
        Form {
            Section {
                TextEditor(text: $settings.trustedCertificateAuthorities)
                    .font(.system(.footnote, design: .monospaced))
                    .frame(minHeight: 140)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            } header: {
                Text("Host certificate authorities")
            } footer: {
                Text("One public key per line: ssh-ed25519 AAAA… ca@example.com. Blank lines and # comments are ignored.")
            }

            let authorities = settings.trustedAuthorities
            if !authorities.entries.isEmpty {
                Section("Recognised") {
                    ForEach(authorities.entries) { entry in
                        AuthorityRow(entry: entry)
                    }
                }
            }

            Section {
                Text("""
                    A host certificate is checked against these keys instead of being pinned on \
                    first use: the certificate has to be signed by one of them, name this host \
                    among its principals, be a host certificate rather than a user one, and still \
                    be inside its validity window.

                    Certificates are never pinned. A certificate's fingerprint changes every time \
                    the CA re-signs the same host key, which is the routine event that a short \
                    validity window exists to cause.
                    """)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("SSH certificates")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct AuthorityRow: View {
    let entry: SSHTrustedAuthorities.Entry

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Image(systemName: entry.isValid ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(entry.isValid ? .green : .orange)
                Text(entry.comment ?? entry.text.split(separator: " ").first.map(String.init) ?? "CA")
                    .font(.callout)
            }
            if let fingerprint = entry.fingerprint {
                Text(fingerprint)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            } else {
                Text("Not a public key line. Paste the contents of the CA's .pub file.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
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
