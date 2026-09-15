import SwiftUI
import UniformTypeIdentifiers

struct IdentitiesView: View {
    @EnvironmentObject private var vault: Vault
    @EnvironmentObject private var settings: AppSettings

    @State private var showingGenerate = false
    @State private var showingImport = false
    @State private var exporting: Identity?
    @State private var pendingDelete: Identity?
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Group {
                if vault.identities.isEmpty {
                    ContentUnavailableView {
                        Label("No keys yet", systemImage: "key")
                    } description: {
                        Text("Generate a key here, then add its public line to the remote host's authorized_keys.")
                    } actions: {
                        Button("Generate key") { showingGenerate = true }
                            .buttonStyle(.borderedProminent)
                    }
                } else {
                    List {
                        ForEach(vault.identities) { identity in
                            Button { exporting = identity } label: { IdentityRow(identity: identity) }
                                .buttonStyle(.plain)
                                .swipeActions(edge: .trailing) {
                                    Button(role: .destructive) { pendingDelete = identity } label: {
                                        Label("Delete", systemImage: "trash")
                                    }
                                }
                        }
                        Section {
                            NavigationLink("Known hosts (\(vault.knownHosts.count))") { KnownHostsView() }
                        }
                    }
                }
            }
            .navigationTitle("Keys")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button {
                            showingGenerate = true
                        } label: { Label("Generate…", systemImage: "wand.and.stars") }
                        Button {
                            showingImport = true
                        } label: { Label("Import…", systemImage: "square.and.arrow.down") }
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("Add key")
                }
            }
            .sheet(isPresented: $showingGenerate) { GenerateIdentityView() }
            .sheet(isPresented: $showingImport) { ImportIdentityView() }
            .sheet(item: $exporting) { ExportIdentityView(identity: $0) }
            .alert("Delete key?", isPresented: .init(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            ), presenting: pendingDelete) { identity in
                Button("Cancel", role: .cancel) {}
                Button("Delete", role: .destructive) { delete(identity) }
            } message: { identity in
                Text("The private key for “\(identity.name)” is removed from the Keychain and cannot be recovered.")
            }
            .alert("Key error", isPresented: .init(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            ), presenting: errorMessage) { _ in
                Button("OK", role: .cancel) {}
            } message: { Text($0) }
        }
    }

    private func delete(_ identity: Identity) {
        do { try vault.deleteIdentity(identity) } catch { errorMessage = error.localizedDescription }
    }
}

struct IdentityRow: View {
    let identity: Identity

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(identity.name).font(.body.weight(.medium))
                Spacer()
                Text(identity.keyType.displayName)
                    .font(.caption2)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.accentColor.opacity(0.18), in: Capsule())
            }
            Text(identity.fingerprint)
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            HStack(spacing: 10) {
                if identity.isSecureEnclave {
                    Label("Secure Enclave", systemImage: "cpu").font(.caption2).foregroundStyle(.green)
                }
                if identity.requiresBiometrics {
                    Label("Face ID", systemImage: "faceid").font(.caption2).foregroundStyle(.blue)
                }
                if identity.syncsToICloud {
                    Label("iCloud", systemImage: "icloud").font(.caption2).foregroundStyle(.orange)
                }
            }
        }
        .padding(.vertical, 3)
        .contentShape(Rectangle())
    }
}

// MARK: - Generate

struct GenerateIdentityView: View {
    @EnvironmentObject private var vault: Vault
    @EnvironmentObject private var settings: AppSettings
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var keyType: SSHKeyType = .ed25519
    @State private var requiresBiometrics = false
    @State private var syncToICloud = false
    @State private var errorMessage: String?
    @State private var generated: Identity?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledField("Name", text: $name, placeholder: "iPhone", autocorrect: false)
                    Picker("Type", selection: $keyType) {
                        ForEach(SSHKeyType.allCases) { type in
                            Text(type.displayName).tag(type)
                        }
                    }
                } footer: {
                    Text(typeFooter)
                }

                Section("Protection") {
                    Toggle("Require Face ID / Touch ID", isOn: $requiresBiometrics)
                    Toggle("Sync via iCloud Keychain", isOn: $syncToICloud)
                        .disabled(keyType.isSecureEnclave || requiresBiometrics)
                    if keyType.isSecureEnclave || requiresBiometrics {
                        Text("Device-bound keys cannot sync: a Secure Enclave key is a reference to this chip, and a biometry policy is tied to this device's enrolled biometrics.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if let generated {
                    Section("Public key") {
                        PublicKeyBlock(line: generated.publicKeyLine)
                    }
                }
            }
            .navigationTitle("Generate key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(generated == nil ? "Cancel" : "Done") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Generate") { generate() }
                        .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || generated != nil)
                }
            }
            .alert("Could not generate", isPresented: .init(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            ), presenting: errorMessage) { _ in
                Button("OK", role: .cancel) {}
            } message: { Text($0) }
            .onAppear { syncToICloud = settings.iCloudSyncDefault }
        }
    }

    private var typeFooter: String {
        switch keyType {
        case .ed25519:
            return "Ed25519 is the default: small, fast, and accepted by every modern OpenSSH."
        case .secureEnclaveP256:
            return "The private key is generated inside the Secure Enclave and can never be read out — not by this app, not by a backup, not by anyone with the device unlocked. It also cannot be exported or moved to another device."
        default:
            return "NIST curve. Use it when the remote host's policy requires ECDSA."
        }
    }

    private func generate() {
        do {
            generated = try vault.generateIdentity(
                name: name.trimmingCharacters(in: .whitespaces),
                type: keyType,
                requiresBiometrics: requiresBiometrics,
                syncToICloud: syncToICloud
            )
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

// MARK: - Import

struct ImportIdentityView: View {
    @EnvironmentObject private var vault: Vault
    @EnvironmentObject private var settings: AppSettings
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var pem = ""
    @State private var syncToICloud = false
    @State private var showingFilePicker = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Name") {
                    LabeledField("Name", text: $name, placeholder: "laptop key", autocorrect: false)
                }
                Section {
                    TextEditor(text: $pem)
                        .font(.caption.monospaced())
                        .frame(minHeight: 180)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    Button {
                        showingFilePicker = true
                    } label: { Label("Choose a file…", systemImage: "folder") }
                    Button {
                        pem = UIPasteboard.general.string ?? pem
                    } label: { Label("Paste from clipboard", systemImage: "doc.on.clipboard") }
                } header: {
                    Text("OpenSSH private key")
                } footer: {
                    Text("Unencrypted openssh-key-v1 only (ed25519 or ECDSA). Decrypt a passphrase-protected key first with: ssh-keygen -p -N \"\" -f key. RSA is not supported — swift-nio-ssh has no RSA client key support at all.")
                }
                Section {
                    Toggle("Sync via iCloud Keychain", isOn: $syncToICloud)
                }
            }
            .navigationTitle("Import key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Import") { importKey() }.disabled(pem.isEmpty)
                }
            }
            .fileImporter(
                isPresented: $showingFilePicker,
                allowedContentTypes: [.data, .text],
                allowsMultipleSelection: false
            ) { result in
                loadFile(result)
            }
            .alert("Could not import", isPresented: .init(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            ), presenting: errorMessage) { _ in
                Button("OK", role: .cancel) {}
            } message: { Text($0) }
            .onAppear { syncToICloud = settings.iCloudSyncDefault }
        }
    }

    private func loadFile(_ result: Result<[URL], Error>) {
        do {
            guard let url = try result.get().first else { return }
            // Files outside the app container need an explicit security scope.
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            pem = try String(contentsOf: url, encoding: .utf8)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func importKey() {
        do {
            _ = try vault.importIdentity(
                name: name.trimmingCharacters(in: .whitespaces),
                pem: pem,
                syncToICloud: syncToICloud
            )
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

// MARK: - Export

struct ExportIdentityView: View {
    @EnvironmentObject private var vault: Vault
    @Environment(\.dismiss) private var dismiss

    let identity: Identity
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Fingerprint") {
                    Text(identity.fingerprint)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
                Section {
                    PublicKeyBlock(line: identity.publicKeyLine)
                } header: {
                    Text("Public key")
                } footer: {
                    Text("Append this line to ~/.ssh/authorized_keys on the remote host.")
                }
                Section {
                    ShareLink(item: identity.publicKeyLine) {
                        Label("Share public key", systemImage: "square.and.arrow.up")
                    }
                } footer: {
                    Text(identity.isSecureEnclave
                         ? "The private key lives in the Secure Enclave and cannot be exported by design."
                         : "The private key stays in the Keychain and is never shared from this screen.")
                }
            }
            .navigationTitle(identity.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
    }
}

struct PublicKeyBlock: View {
    let line: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(line)
                .font(.caption2.monospaced())
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                UIPasteboard.general.string = line
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
        .padding(.vertical, 4)
    }
}
