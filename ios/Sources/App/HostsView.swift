import SwiftUI

struct HostsView: View {
    @EnvironmentObject private var vault: Vault
    @EnvironmentObject private var settings: AppSettings
    @EnvironmentObject private var sessions: SessionManager

    @State private var search = ""
    @State private var editing: Host?
    @State private var showingNew = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Group {
                if vault.hosts.isEmpty {
                    ContentUnavailableView {
                        Label("No hosts yet", systemImage: "server.rack")
                    } description: {
                        Text("iOS has no shell, so Ghostty talks to a machine that does. Add one to get started.")
                    } actions: {
                        Button("Add host") { showingNew = true }
                            .buttonStyle(.borderedProminent)
                    }
                } else {
                    list
                }
            }
            .navigationTitle("Hosts")
            .searchable(text: $search, prompt: "Search hosts")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showingNew = true } label: { Image(systemName: "plus") }
                        .accessibilityLabel("Add host")
                }
            }
            .sheet(isPresented: $showingNew) {
                HostEditorView(host: Host(term: settings.defaultTerm))
            }
            .sheet(item: $editing) { host in
                HostEditorView(host: host)
            }
            .alert("Could not connect", isPresented: .init(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            ), presenting: errorMessage) { _ in
                Button("OK", role: .cancel) {}
            } message: { Text($0) }
        }
    }

    private var list: some View {
        List {
            ForEach(groups, id: \.name) { group in
                Section(group.name) {
                    ForEach(group.hosts) { host in
                        Button {
                            connect(host)
                        } label: {
                            HostRow(host: host, identity: vault.identity(withID: host.identityID))
                        }
                        .buttonStyle(.plain)
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                Haptics.shared.fire(.listAction)
                                vault.deleteHost(host)
                            } label: { Label("Delete", systemImage: "trash") }
                            Button {
                                Haptics.shared.fire(.listAction)
                                editing = host
                            } label: { Label("Edit", systemImage: "pencil") }
                                .tint(.blue)
                        }
                    }
                }
            }
        }
    }

    private var filtered: [Host] {
        guard !search.isEmpty else { return vault.hosts }
        let needle = search.lowercased()
        return vault.hosts.filter {
            $0.alias.lowercased().contains(needle)
                || $0.hostname.lowercased().contains(needle)
                || $0.username.lowercased().contains(needle)
                || $0.tags.contains { $0.lowercased().contains(needle) }
        }
    }

    private var groups: [(name: String, hosts: [Host])] {
        Dictionary(grouping: filtered, by: { $0.group.isEmpty ? "Ungrouped" : $0.group })
            .map { (name: $0.key, hosts: $0.value.sorted { $0.displayName < $1.displayName }) }
            .sorted { $0.name < $1.name }
    }

    private func connect(_ host: Host) {
        do {
            // The Sessions tab comes forward via SessionManager's tab request,
            // so the caller does not have to know about navigation.
            try sessions.connect(to: host)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private struct HostRow: View {
    let host: Host
    let identity: Identity?

    var body: some View {
        HStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 4)
                .fill(accent)
                .frame(width: 4, height: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text(host.displayName).font(.body.weight(.medium))
                Text("\(host.username)@\(host.destination)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                if let identity {
                    Label(identity.name, systemImage: "key.fill")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                } else if host.usesPassword {
                    Label("password", systemImage: "lock.fill")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if !host.tags.isEmpty {
                    Text(host.tags.joined(separator: " · "))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .padding(.vertical, 2)
        .contentShape(Rectangle())
    }

    private var accent: Color {
        guard let hex = host.colorHex, let color = VTColor(hex: hex) else { return .accentColor }
        return Color(color.cgColor)
    }
}

// MARK: - Editor

struct HostEditorView: View {
    @EnvironmentObject private var vault: Vault
    @Environment(\.dismiss) private var dismiss

    @State var host: Host
    @State private var password = ""
    @State private var tagText = ""
    @State private var errorMessage: String?
    @State private var testing = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Connection") {
                    LabeledField("Alias", text: $host.alias, placeholder: "noether")
                    LabeledField("Host", text: $host.hostname, placeholder: "10.0.0.81", autocorrect: false)
                    HStack {
                        Text("Port")
                        Spacer()
                        TextField("22", value: $host.port, format: .number)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                            .frame(width: 80)
                    }
                    LabeledField("User", text: $host.username, placeholder: "andy", autocorrect: false)
                }

                Section("Authentication") {
                    Picker("Identity", selection: $host.identityID) {
                        Text("Password").tag(UUID?.none)
                        ForEach(vault.identities) { identity in
                            Text(identity.name).tag(UUID?.some(identity.id))
                        }
                    }
                    if host.identityID == nil {
                        SecureField("Password (stored in Keychain)", text: $password)
                            .textContentType(.password)
                        Text("Saved to the Keychain as accessible-when-unlocked, this device only. It never touches the JSON on disk.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Section("Terminal") {
                    LabeledField("TERM", text: $host.term, placeholder: "xterm-256color", autocorrect: false)
                    Text("Remote hosts rarely have ghostty's terminfo installed; xterm-256color is what they do have.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    LabeledField("Startup command", text: Binding(
                        get: { host.startupCommand ?? "" },
                        set: { host.startupCommand = $0.isEmpty ? nil : $0 }
                    ), placeholder: "tmux attach", autocorrect: false)
                }

                Section {
                    Button {
                        testing = true
                    } label: {
                        Label("Test connection", systemImage: "stethoscope")
                    }
                    .disabled(!isValid)
                } footer: {
                    Text("""
                        Connects far enough to read the server's banner, compare its \
                        algorithms with the ones this app supports, and show its host key \
                        fingerprint. Credentials are only offered once that key is pinned, \
                        and no shell or command is ever started.
                        """)
                }

                Section("Organisation") {
                    LabeledField("Group", text: $host.group, placeholder: "homelab")
                    LabeledField("Tags", text: $tagText, placeholder: "linux, pi", autocorrect: false)
                    LabeledField("Notes", text: $host.notes, placeholder: "")
                }
            }
            .navigationTitle(host.hostname.isEmpty ? "New host" : host.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }.disabled(!isValid)
                }
            }
            .sheet(isPresented: $testing) {
                ConnectionTestView(host: host)
            }
            .onAppear {
                tagText = host.tags.joined(separator: ", ")
                password = (try? vault.password(for: host)) ?? ""
            }
            .alert("Could not save", isPresented: .init(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            ), presenting: errorMessage) { _ in
                Button("OK", role: .cancel) {}
            } message: { Text($0) }
        }
    }

    private var isValid: Bool {
        !host.hostname.trimmingCharacters(in: .whitespaces).isEmpty
            && !host.username.trimmingCharacters(in: .whitespaces).isEmpty
            && (1...65535).contains(host.port)
    }

    private func save() {
        var updated = host
        updated.tags = tagText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        updated.usesPassword = updated.identityID == nil && !password.isEmpty
        vault.upsert(updated)
        do {
            if updated.identityID == nil {
                try vault.setPassword(password.isEmpty ? nil : password, for: updated)
            }
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

struct LabeledField: View {
    let label: String
    @Binding var text: String
    var placeholder: String = ""
    var autocorrect = true

    init(_ label: String, text: Binding<String>, placeholder: String = "", autocorrect: Bool = true) {
        self.label = label
        self._text = text
        self.placeholder = placeholder
        self.autocorrect = autocorrect
    }

    var body: some View {
        HStack {
            Text(label)
            Spacer()
            TextField(placeholder, text: $text)
                .multilineTextAlignment(.trailing)
                .autocorrectionDisabled(!autocorrect)
                .textInputAutocapitalization(autocorrect ? .sentences : .never)
        }
    }
}
