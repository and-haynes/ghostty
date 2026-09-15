import SwiftUI
import UniformTypeIdentifiers

struct SyncProviderRow: View {
    let kind: VaultSyncProviderKind
    let status: VaultSyncStatus
    let busy: Bool

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: kind.systemImage)
                .font(.title3)
                .frame(width: 28)
                .foregroundStyle(status.isConnected ? Color.accentColor : .secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(kind.displayName).font(.body)
                if busy {
                    Text("Syncing…").font(.caption).foregroundStyle(.secondary)
                } else if let account = status.accountLabel, status.isConnected {
                    Text(account).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                } else {
                    Text("Not connected").font(.caption).foregroundStyle(.tertiary)
                }
                if let result = status.lastResult {
                    Text(result)
                        .font(.caption2)
                        .foregroundStyle(status.lastResultWasError ? Color.red : .secondary)
                        .lineLimit(2)
                }
            }
            Spacer()
            if busy {
                ProgressView()
            } else if status.isConnected {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            }
        }
        .padding(.vertical, 2)
    }
}

/// Connect / sync / disconnect for one provider.
struct SyncProviderView: View {
    @EnvironmentObject private var sync: VaultSyncEngine
    let kind: VaultSyncProviderKind

    // Bitwarden
    @State private var serverURL = "https://vault.lan"
    @State private var email = ""
    @State private var masterPassword = ""
    @State private var totp = ""
    @State private var useAPIKey = false
    @State private var clientID = ""
    @State private var clientSecret = ""
    @State private var allowSelfSigned = false

    // 1Password Connect
    @State private var connectURL = ""
    @State private var connectToken = ""
    @State private var vaultName = ""

    // Bundle
    @State private var passphrase = ""
    @State private var showingExporter = false
    @State private var showingImporter = false
    @State private var shareURL: URL?

    private var status: VaultSyncStatus { sync.status(kind) }
    private var busy: Bool { sync.isBusy(kind) }

    var body: some View {
        Form {
            Section {
                Text(sync.provider(kind)?.helpText ?? "")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            if status.isConnected {
                Section("Status") {
                    LabeledContent("Account", value: status.accountLabel ?? "—")
                    LabeledContent("Last sync", value: status.lastSync.map {
                        $0.formatted(date: .abbreviated, time: .shortened)
                    } ?? "never")
                    if let result = status.lastResult {
                        Text(result)
                            .font(.caption)
                            .foregroundStyle(status.lastResultWasError ? Color.red : .secondary)
                    }
                }
                Section {
                    Button("Sync now", systemImage: "arrow.triangle.2.circlepath") {
                        Task { await sync.syncNow(kind) }
                    }
                    .disabled(busy)
                    if kind == .encryptedBundle {
                        bundleFileActions
                    }
                    Button("Disconnect", systemImage: "xmark.circle", role: .destructive) {
                        Task { await sync.disconnect(kind) }
                    }
                    .disabled(busy)
                }
            } else {
                connectForm
            }
        }
        .navigationTitle(kind.displayName)
        .navigationBarTitleDisplayMode(.inline)
        .fileImporter(
            isPresented: $showingImporter,
            // The exported bundle declares its own UTType (see Info.plist), so
            // the picker can filter for it instead of showing every file.
            allowedContentTypes: [UTType(exportedAs: "com.morton.ghostty.vault-bundle"), .data],
            allowsMultipleSelection: false
        ) { result in
            if let url = try? result.get().first {
                (sync.provider(kind) as? EncryptedBundleProvider)?.pendingImportFileURL = url
                Task { await sync.syncNow(kind) }
            }
        }
        .sheet(item: Binding(
            get: { shareURL.map { ShareItem(url: $0) } },
            set: { if $0 == nil { shareURL = nil } }
        )) { item in
            ActivityView(url: item.url)
        }
    }

    // MARK: - Connect forms

    @ViewBuilder
    private var connectForm: some View {
        switch kind {
        case .iCloudKeychain:
            Section {
                Button("Connect", systemImage: "icloud") {
                    Task { await sync.connect(kind, credentials: .none) }
                }
                .disabled(busy)
            } footer: {
                Text("Uses the iCloud account this device is signed into. Nothing to enter.")
            }

        case .bitwarden:
            Section {
                TextField("https://vault.lan", text: $serverURL)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
            } header: {
                Text("Server")
            }
            Section {
                Picker("Sign in with", selection: $useAPIKey) {
                    Text("Email + password").tag(false)
                    Text("API key").tag(true)
                }
                .pickerStyle(.segmented)

                if useAPIKey {
                    TextField("client_id", text: $clientID)
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                    SecureField("client_secret", text: $clientSecret)
                } else {
                    TextField("Email", text: $email)
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                }
                SecureField("Master password", text: $masterPassword)
                if !useAPIKey {
                    TextField("Two-factor code (if enabled)", text: $totp)
                        .keyboardType(.numberPad)
                }
            } footer: {
                Text("The master password never leaves the device: it derives the keys locally, and only a one-iteration hash of it is sent, exactly as the official clients do.")
            }
            Section {
                Toggle("Trust a self-signed certificate", isOn: $allowSelfSigned)
            } footer: {
                Text("Only for a server on your own network whose certificate iOS does not know — a homelab Vaultwarden, typically. Validation is relaxed for that one host and nothing else. The properly boring fix is installing your CA as a device trust profile.")
            }
            Section {
                Button("Connect", systemImage: "shield.lefthalf.filled") { connectBitwarden() }
                    .disabled(busy || !bitwardenReady)
            }

        case .onePasswordConnect:
            Section {
                TextField("https://connect.lan", text: $connectURL)
                    .autocorrectionDisabled().textInputAutocapitalization(.never).keyboardType(.URL)
                SecureField("Connect token", text: $connectToken)
                TextField("Vault name (optional)", text: $vaultName)
                    .autocorrectionDisabled()
                Toggle("Trust a self-signed certificate", isOn: $allowSelfSigned)
            } header: {
                Text("Connect server")
            } footer: {
                Text("A Connect server is usually self-hosted. Relaxing validation applies to that one host only.")
            }
            Section {
                Button("Connect", systemImage: "lock.square.stack") {
                    guard let url = URL(string: connectURL.trimmingCharacters(in: .whitespaces)) else { return }
                    (sync.provider(kind) as? OnePasswordConnectProvider)?
                        .allowsSelfSignedCertificates = allowSelfSigned
                    Task {
                        await sync.connect(kind, credentials: .onePasswordConnect(
                            serverURL: url,
                            token: connectToken,
                            vaultName: vaultName.isEmpty ? nil : vaultName
                        ))
                    }
                }
                .disabled(busy || connectURL.isEmpty || connectToken.isEmpty)
            } footer: {
                Text("1Password has no on-device API for third-party apps — no extension, no local vault access. Connect is a small REST server you host yourself; this is the only supported route.")
            }

        case .encryptedBundle:
            Section {
                SecureField("Passphrase", text: $passphrase)
            } header: {
                Text("Passphrase")
            } footer: {
                Text("The bundle is only as safe as this passphrase. Use a long one — it is the single thing between the file and every key in it.")
            }
            Section {
                Button("Use this passphrase", systemImage: "doc.zipper") {
                    Task { await sync.connect(kind, credentials: .bundlePassphrase(passphrase)) }
                }
                .disabled(busy || passphrase.count < 8)
            }
        }
    }

    private var bitwardenReady: Bool {
        guard !masterPassword.isEmpty, URL(string: serverURL) != nil else { return false }
        return useAPIKey ? (!clientID.isEmpty && !clientSecret.isEmpty) : !email.isEmpty
    }

    private func connectBitwarden() {
        guard let url = URL(string: serverURL.trimmingCharacters(in: .whitespaces)) else { return }
        // Set before connect: the flag is read when the client is built.
        (sync.provider(kind) as? BitwardenSyncProvider)?
            .allowsSelfSignedCertificates = allowSelfSigned
        let credentials: VaultSyncCredentials = useAPIKey
            ? .bitwardenAPIKey(
                serverURL: url,
                clientID: clientID.trimmingCharacters(in: .whitespaces),
                clientSecret: clientSecret,
                masterPassword: masterPassword
            )
            : .bitwardenPassword(
                serverURL: url,
                email: email.trimmingCharacters(in: .whitespaces),
                masterPassword: masterPassword,
                totp: totp.isEmpty ? nil : totp
            )
        Task { await sync.connect(kind, credentials: credentials) }
    }

    @ViewBuilder
    private var bundleFileActions: some View {
        Button("Export and share…", systemImage: "square.and.arrow.up") {
            Task {
                await sync.syncNow(kind)
                shareURL = (sync.provider(kind) as? EncryptedBundleProvider)?.lastExportedFileURL
            }
        }
        .disabled(busy)
        Button("Import from Files…", systemImage: "square.and.arrow.down") {
            showingImporter = true
        }
        .disabled(busy)
    }
}

private struct ShareItem: Identifiable {
    let url: URL
    var id: URL { url }
}

/// UIActivityViewController, because SwiftUI's ShareLink cannot share a file
/// URL that is produced asynchronously by a button in the same view.
private struct ActivityView: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [url], applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
