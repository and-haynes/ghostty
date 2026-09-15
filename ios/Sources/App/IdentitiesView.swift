import SwiftUI
import UniformTypeIdentifiers

struct IdentitiesView: View {
    @EnvironmentObject private var vault: Vault

    @State private var showingGenerate = false
    @State private var showingOnePasswordGuide = false
    @State private var exporting: Identity?
    @State private var pendingDelete: Identity?
    @State private var errorMessage: String?
    /// Whether the clipboard *might* hold a key. Only `hasStrings` is consulted
    /// here — reading the contents raises the system paste banner, and doing
    /// that every time this tab appears would be rude and useless.
    @State private var clipboardMayHaveKey = false
    /// The import sheet's payload.
    ///
    /// `.sheet(item:)` rather than `.sheet(isPresented:)` on purpose: when the
    /// text and the presentation flag are set in the same update — which is
    /// exactly what happens when the paste control hands over a key — the
    /// `isPresented` form can build its content from the *previous* values and
    /// present an empty sheet. Carrying the payload in the item makes that
    /// impossible.
    @State private var pendingImport: PendingKeyImport?

    var body: some View {
        NavigationStack {
            Group {
                if vault.identities.isEmpty {
                    ContentUnavailableView {
                        Label("No keys yet", systemImage: "key")
                    } description: {
                        Text("Generate a key here, then add its public line to the remote host's authorized_keys.")
                    } actions: {
                        VStack(spacing: 12) {
                            Button("Generate key") { showingGenerate = true }
                                .buttonStyle(.borderedProminent)
                            if clipboardMayHaveKey {
                                HStack(spacing: 8) {
                                    Text("Copied a key?")
                                        .font(.callout)
                                        .foregroundStyle(.secondary)
                                    PasteKeyControl { text in handlePastedKey(text) }
                                        .frame(width: 96, height: 34)
                                }
                            }
                            Button("Import from 1Password…") { showingOnePasswordGuide = true }
                                .font(.callout)
                        }
                    }
                } else {
                    List {
                        ForEach(vault.identities) { identity in
                            Button { exporting = identity } label: { IdentityRow(identity: identity) }
                                .buttonStyle(.plain)
                                .swipeActions(edge: .trailing) {
                                    Button(role: .destructive) {
                                        Haptics.shared.fire(.listAction)
                                        pendingDelete = identity
                                    } label: {
                                        Label("Delete", systemImage: "trash")
                                    }
                                }
                        }
                        if clipboardMayHaveKey {
                            Section {
                                HStack {
                                    Label("Import key from clipboard", systemImage: "doc.on.clipboard")
                                    Spacer()
                                    PasteKeyControl { text in handlePastedKey(text) }
                                        .frame(width: 96, height: 34)
                                }
                            } footer: {
                                Text("""
                                    Copied a private key out of 1Password? One tap. The system \
                                    Paste button hands it over without an "Allow Paste" prompt, \
                                    and the clipboard is wiped once the key is saved.
                                    """)
                            }
                        }
                        Section {
                            NavigationLink("Known hosts (\(vault.knownHosts.count))") { KnownHostsView() }
                            Button("Import from 1Password…") { showingOnePasswordGuide = true }
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
                            pendingImport = PendingKeyImport(pem: "", name: "", fromClipboard: false)
                        } label: { Label("Import…", systemImage: "square.and.arrow.down") }
                        Button {
                            showingOnePasswordGuide = true
                        } label: { Label("Import from 1Password…", systemImage: "questionmark.circle") }
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("Add key")
                }
            }
            .sheet(isPresented: $showingGenerate) { GenerateIdentityView() }
            .sheet(item: $pendingImport) { pending in
                ImportIdentityView(
                    prefilledPEM: pending.pem,
                    suggestedName: pending.name,
                    cameFromClipboard: pending.fromClipboard
                )
            }
            .sheet(isPresented: $showingOnePasswordGuide) { OnePasswordImportGuide() }
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
            .onAppear { refreshClipboardOffer() }
        }
    }

    /// Re-checked on every appearance, because the user has usually just been
    /// in another app copying something.
    private func refreshClipboardOffer() {
        clipboardMayHaveKey = ClipboardKeyImport.mayHaveKey
    }

    /// Text arrived from the system paste control. Open the import sheet on it
    /// when it is a key, and say why when it is not.
    private func handlePastedKey(_ text: String) {
        switch ClipboardKeyImport.classify(text) {
        case .key(let pem, _, let suggested):
            pendingImport = PendingKeyImport(pem: pem, name: suggested, fromClipboard: true)
        case .encryptedKey:
            pendingImport = PendingKeyImport(pem: text, name: "", fromClipboard: true)
        case .notAKey:
            errorMessage = """
                That is not a private key. In 1Password, open the SSH key item, reveal \
                the private key and copy that — not the public key, and not the item.
                """
        case .empty:
            errorMessage = "The clipboard is empty."
        }
    }

    private func delete(_ identity: Identity) {
        do { try vault.deleteIdentity(identity) } catch { errorMessage = error.localizedDescription }
    }
}

/// The import sheet's payload. Identifiable so `.sheet(item:)` can carry it.
private struct PendingKeyImport: Identifiable {
    let id = UUID()
    var pem: String
    var name: String
    var fromClipboard: Bool
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
                if !identity.keyType.canAuthenticate {
                    Label("export only", systemImage: "exclamationmark.triangle")
                        .font(.caption2)
                        .foregroundStyle(.orange)
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
                        // `generatable` rather than `allCases`: RSA can be
                        // imported but not used, and offering to generate one
                        // would be a trap.
                        ForEach(SSHKeyType.generatable) { type in
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
        case .rsa:
            return """
                RSA keys can be imported and exported but not used to connect: \
                swift-nio-ssh cannot sign with them.
                """
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
            Haptics.shared.fire(.keyGenerated)
        } catch {
            errorMessage = error.localizedDescription
            Haptics.shared.fire(.syncFailed)
        }
    }
}

// MARK: - Import

struct ImportIdentityView: View {
    @EnvironmentObject private var vault: Vault
    @EnvironmentObject private var settings: AppSettings
    @Environment(\.dismiss) private var dismiss

    /// Key text already obtained from the system paste control, so this sheet
    /// never has to touch the pasteboard itself.
    var prefilledPEM: String = ""
    var suggestedName: String = ""
    var cameFromClipboard: Bool = false

    @State private var name = ""
    @State private var pem = ""
    @State private var syncToICloud = false
    @State private var showingFilePicker = false
    @State private var showingOnePasswordGuide = false
    @State private var errorMessage: String?
    @State private var clipboardMayHaveKey = false
    /// True once the key in the editor came from the clipboard, so a successful
    /// import can wipe it. Starts from `cameFromClipboard` and is set again by
    /// an in-sheet paste.
    @State private var wipeClipboardOnImport = false

    /// What the pasted text appears to be, recomputed as it changes so the
    /// footer can say something useful before the user taps Import.
    private var detectedFormat: PEMKeyFormat {
        pem.isEmpty ? .unrecognised : PEMPrivateKey.detect(pem)
    }

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
                    if clipboardMayHaveKey {
                        HStack {
                            Label("From the clipboard", systemImage: "doc.on.clipboard")
                            Spacer()
                            PasteKeyControl { text in absorb(text) }
                                .frame(width: 96, height: 34)
                        }
                    }
                } header: {
                    Text("Private key")
                } footer: {
                    Text(footerText)
                }
                Section {
                    Toggle("Sync via iCloud Keychain", isOn: $syncToICloud)
                }
                Section {
                    Button {
                        showingOnePasswordGuide = true
                    } label: {
                        Label("Import from 1Password…", systemImage: "questionmark.circle")
                    }
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
            .sheet(isPresented: $showingOnePasswordGuide) { OnePasswordImportGuide() }
            .alert("Could not import", isPresented: .init(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            ), presenting: errorMessage) { _ in
                Button("OK", role: .cancel) {}
            } message: { Text($0) }
            .onAppear {
                syncToICloud = settings.iCloudSyncDefault
                clipboardMayHaveKey = ClipboardKeyImport.mayHaveKey
                if pem.isEmpty, !prefilledPEM.isEmpty { pem = prefilledPEM }
                if cameFromClipboard { wipeClipboardOnImport = true }
                if name.isEmpty, !suggestedName.isEmpty { name = suggestedName }
            }
        }
    }

    /// Says what the pasted text is, or what is accepted when there is none.
    private var footerText: String {
        guard !pem.isEmpty else {
            return """
                OpenSSH (-----BEGIN OPENSSH PRIVATE KEY-----), PKCS#8 (-----BEGIN PRIVATE \
                KEY-----), PKCS#1 RSA and SEC 1 EC keys, unencrypted. Ed25519, ECDSA \
                P-256/384/521 and RSA. Decrypt a passphrase-protected key first with: \
                ssh-keygen -p -N "" -f key
                """
        }
        switch detectedFormat {
        case .encrypted:
            return """
                This key is passphrase-protected. Decrypt a copy first: \
                ssh-keygen -p -N "" -f key
                """
        case .unrecognised:
            return """
                No private key found in that text. PuTTY .ppk files and DSA keys are not \
                supported; public keys go in the server's authorized_keys, not here.
                """
        default:
            var text = "Looks like a \(detectedFormat.displayName)."
            if let parsed = try? PEMPrivateKey.parse(pem) {
                text += " \(parsed.material.keyType.displayName)."
                if !parsed.material.keyType.canAuthenticate {
                    text += """
                         It can be stored, fingerprinted and exported, but the SSH library \
                        this app is built on cannot sign with RSA, so it cannot connect \
                        with it yet.
                        """
                }
            }
            return text
        }
    }

    /// Take text handed over by the system paste control.
    private func absorb(_ text: String) {
        switch ClipboardKeyImport.classify(text) {
        case .key(let key, _, let suggested):
            pem = key
            wipeClipboardOnImport = true
            if name.trimmingCharacters(in: .whitespaces).isEmpty { name = suggested }
        case .encryptedKey:
            pem = text
            wipeClipboardOnImport = true
        case .notAKey:
            errorMessage = """
                That is not a private key. In 1Password, open the SSH key item, reveal \
                the private key and copy that — not the public key, and not the item.
                """
        case .empty:
            errorMessage = "There was nothing on the clipboard."
        }
    }

    private func loadFile(_ result: Result<[URL], Error>) {
        do {
            guard let url = try result.get().first else { return }
            // Files outside the app container need an explicit security scope.
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            pem = try String(contentsOf: url, encoding: .utf8)
            wipeClipboardOnImport = false
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
            // A private key left on the system pasteboard is readable by the
            // next app the user opens, and by any Mac on the same iCloud
            // account through Universal Clipboard. The user is finished with
            // it; take it away.
            if wipeClipboardOnImport { ClipboardKeyImport.clear() }
            Haptics.shared.fire(.keyGenerated)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
            Haptics.shared.fire(.syncFailed)
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
                if !identity.keyType.canAuthenticate {
                    Section {
                        Label {
                            Text("""
                                This key can be stored, fingerprinted and exported, but \
                                Ghostty cannot connect with it: swift-nio-ssh has no RSA \
                                client key support and no way to add one from outside the \
                                library. Use an Ed25519 key to connect.
                                """)
                            .font(.callout)
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        }
                    }
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
