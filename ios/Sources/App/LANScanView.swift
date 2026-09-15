import SwiftUI

/// Scan the local network for things worth connecting to.
///
/// This is a convenience, not a security tool: it knocks on a curated list of
/// TCP ports and reports what answered. It never authenticates — the closest
/// it comes is reading the SSH identification banner every server sends
/// unprompted the moment you connect.
struct LANScanView: View {
    @EnvironmentObject private var vault: Vault
    @EnvironmentObject private var settings: AppSettings
    @StateObject private var scanner = LANScanner()
    @StateObject private var pinner: HostKeyPinner

    @State private var selection: Set<String> = []
    /// Alias overrides, keyed by address. Editing the name at the point of
    /// import is the only moment anyone knows which of six anonymous 10.0.0.x
    /// boxes is the NAS, so the field belongs in the results row rather than
    /// in a host editor five taps later.
    @State private var aliases: [String: String] = [:]
    @State private var portMode: PortMode = .curated
    @State private var customPorts = ""
    @State private var username = ""
    @State private var showingLowPortWarning = false
    @FocusState private var focusedField: Field?
    @State private var importSummary: String?
    @State private var showingPinResults = false

    init(vault: Vault) {
        _pinner = StateObject(wrappedValue: HostKeyPinner(vault: vault))
    }

    private enum Field: Hashable { case customPorts, username }

    enum PortMode: String, CaseIterable, Identifiable {
        case curated, custom, allLow
        var id: String { rawValue }
        var title: String {
            switch self {
            case .curated: return "Common"
            case .custom: return "Custom"
            case .allLow: return "1–1024"
            }
        }
    }

    var body: some View {
        List {
            controls
            if let warning = scanner.warning {
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            if let error = scanner.lastError {
                Label(error, systemImage: "xmark.octagon")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            results
        }
        .scrollDismissesKeyboard(.immediately)
        .navigationTitle("Scan local network")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                if scanner.isScanning {
                    Button("Cancel") { scanner.cancel() }
                } else {
                    Button("Scan") { startScan() }
                }
            }
        }
        .onAppear {
            guard username.isEmpty else { return }
            username = settings.lastUsername.isEmpty
                ? (vault.commonUsername ?? "")
                : settings.lastUsername
        }
        .alert("Scan all ports 1–1024?", isPresented: $showingLowPortWarning) {
            Button("Cancel", role: .cancel) {}
            Button("Scan anyway") { runScan(ports: PortCatalog.lowPorts) }
        } message: {
            Text("That is 1024 probes per host instead of 18. On a /24 it is a few minutes and a lot of radio time.")
        }
        .alert("Imported", isPresented: .init(
            get: { importSummary != nil },
            set: { if !$0 { importSummary = nil } }
        ), presenting: importSummary) { _ in
            Button("OK", role: .cancel) {}
        } message: { Text($0) }
        .sheet(isPresented: $showingPinResults) {
            PinResultsView(pinner: pinner)
        }
    }

    // MARK: - Controls

    @ViewBuilder
    private var controls: some View {
        Section {
            Picker("Ports", selection: $portMode) {
                ForEach(PortMode.allCases) { mode in Text(mode.title).tag(mode) }
            }
            .pickerStyle(.segmented)

            if portMode == .custom {
                TextField("22, 8080, 9090", text: $customPorts)
                    .keyboardType(.numbersAndPunctuation)
                    .autocorrectionDisabled()
                    .focused($focusedField, equals: .customPorts)
                    .submitLabel(.done)
                    .onSubmit { focusedField = nil }
            }

            LabeledField("Username", text: $username, placeholder: "andy", autocorrect: false)
                .focused($focusedField, equals: .username)

            if let subnet = scanner.subnetDescription {
                HStack {
                    Text("Network")
                    Spacer()
                    Text(subnet).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }

            if scanner.isScanning {
                VStack(alignment: .leading, spacing: 4) {
                    ProgressView(value: scanner.progress)
                    Text(scanner.statusLine).font(.caption).foregroundStyle(.secondary)
                }
            } else if !scanner.statusLine.isEmpty {
                Text(scanner.statusLine).font(.caption).foregroundStyle(.secondary)
            }
        } header: {
            Text("Scan")
        } footer: {
            Text("Knocks on TCP ports and reads the SSH banner servers send unprompted. Nothing is authenticated and nothing is written to any host.")
        }
    }

    // MARK: - Results

    @ViewBuilder
    private var results: some View {
        if scanner.hosts.isEmpty {
            if !scanner.isScanning {
                Section {
                    Text("No results yet. Tap Scan.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        } else {
            Section {
                ForEach(scanner.hosts) { host in
                    LANHostRow(
                        host: host,
                        selected: selection.contains(host.id),
                        alias: aliasBinding(for: host),
                        onTap: { toggle(host) }
                    )
                }
            } header: {
                Text("\(scanner.hosts.count) host\(scanner.hosts.count == 1 ? "" : "s")")
            }

            Section {
                Button("Import \(selection.isEmpty ? "all" : "\(selection.count) selected")", systemImage: "square.and.arrow.down") {
                    importSelected()
                }
                Button("Pin host keys", systemImage: "lock.shield") {
                    pinSelected()
                }
                .disabled(pinner.isRunning || sshHostsToPin.isEmpty)
                if pinner.isRunning {
                    ProgressView(value: pinner.progress)
                }
            } footer: {
                Text("Importing turns SSH ports into hosts in the \"Local\" group; everything else is kept as a local service for reference. Pinning connects far enough to read each host key and records it — authentication is never attempted.")
            }
        }
    }

    private var chosenHosts: [LANHost] {
        selection.isEmpty ? scanner.hosts : scanner.hosts.filter { selection.contains($0.id) }
    }

    /// Pin what is already in the vault, so the fingerprints recorded are for
    /// hosts the user actually kept rather than for every address that
    /// happened to answer on 22.
    private var sshHostsToPin: [Host] {
        LANImporter.sshHosts(in: vault, matching: chosenHosts)
    }

    private func toggle(_ host: LANHost) {
        Haptics.shared.fire(.selectionChip)
        if selection.contains(host.id) {
            selection.remove(host.id)
        } else {
            selection.insert(host.id)
            if aliases[host.id] == nil { aliases[host.id] = host.displayName }
        }
    }

    private func aliasBinding(for host: LANHost) -> Binding<String> {
        Binding(
            get: { aliases[host.id] ?? host.displayName },
            set: { aliases[host.id] = $0 }
        )
    }

    private func alias(for host: LANHost) -> String {
        let chosen = (aliases[host.id] ?? host.displayName).trimmingCharacters(in: .whitespaces)
        return chosen.isEmpty ? host.address : chosen
    }

    // MARK: - Actions

    private func startScan() {
        // Put the keyboard away: a scan is something you watch, and a numeric
        // keypad covers most of the results list on a phone.
        focusedField = nil
        settings.lastUsername = username
        switch portMode {
        case .curated:
            runScan(ports: PortCatalog.curated.map(\.port))
        case .custom:
            let ports = customPorts
                .split(whereSeparator: { ",; ".contains($0) })
                .compactMap { Int($0) }
                .filter { (1...65535).contains($0) }
            runScan(ports: ports.isEmpty ? PortCatalog.curated.map(\.port) : ports)
        case .allLow:
            showingLowPortWarning = true
        }
    }

    private func runScan(ports: [Int]) {
        Task { await scanner.scan(ports: ports) }
    }

    private func importSelected() {
        let results = chosenHosts
        guard !results.isEmpty else { return }
        let user = LANImporter.resolveUsername(username, in: vault)
        if !user.isEmpty { settings.lastUsername = user }

        let summary = LANImporter.import(
            results,
            into: vault,
            username: user,
            term: settings.defaultTerm,
            aliases: aliases
        )
        Haptics.shared.fire(summary.isEmpty ? .syncFailed : .syncSucceeded)
        importSummary = summary.description
    }

    private func pinSelected() {
        let hosts = sshHostsToPin
        showingPinResults = true
        Task { await pinner.pin(hosts) }
    }
}

private struct LANHostRow: View {
    let host: LANHost
    let selected: Bool
    @Binding var alias: String
    let onTap: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            summaryButton
            if selected {
                HStack(spacing: 8) {
                    Image(systemName: "pencil").font(.caption2).foregroundStyle(.secondary)
                    TextField("Name", text: $alias)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .font(.callout)
                }
                .padding(.leading, 26)
            }
        }
    }

    private var summaryButton: some View {
        Button(action: onTap) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selected ? Color.accentColor : .secondary)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(host.displayName).font(.body.weight(.medium))
                        if host.hasSSH {
                            Image(systemName: "terminal").font(.caption2).foregroundStyle(.green)
                        }
                    }
                    if host.hostname != nil {
                        Text(host.address).font(.caption2.monospaced()).foregroundStyle(.secondary)
                    }
                    if !host.bonjourServices.isEmpty {
                        Text(host.bonjourServices.joined(separator: " · "))
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    Text(host.summary)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    if let banner = host.sshPorts.compactMap(\.banner).first {
                        Text(banner).font(.caption2.monospaced()).foregroundStyle(.tertiary).lineLimit(1)
                    }
                }
                Spacer()
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

private struct PinResultsView: View {
    @ObservedObject var pinner: HostKeyPinner
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                ForEach(pinner.results) { result in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(result.id).font(.body.monospaced())
                        switch result.outcome {
                        case .pinned(let fingerprint, let keyType):
                            Label("pinned · \(keyType)", systemImage: "checkmark.seal")
                                .font(.caption).foregroundStyle(.green)
                            Text(fingerprint).font(.caption2.monospaced()).foregroundStyle(.secondary)
                        case .unchanged(let fingerprint):
                            Label("already pinned", systemImage: "checkmark")
                                .font(.caption).foregroundStyle(.secondary)
                            Text(fingerprint).font(.caption2.monospaced()).foregroundStyle(.secondary)
                        case .changed(let expected, let presented):
                            Label("KEY CHANGED — not re-pinned", systemImage: "exclamationmark.triangle.fill")
                                .font(.caption.weight(.bold)).foregroundStyle(.red)
                            Text("pinned:    \(expected)").font(.caption2.monospaced())
                            Text("presented: \(presented)").font(.caption2.monospaced())
                        case .unreachable(let reason):
                            Label(reason, systemImage: "wifi.slash")
                                .font(.caption).foregroundStyle(.orange)
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
            .navigationTitle(pinner.isRunning ? "Pinning…" : pinner.summary)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }.disabled(pinner.isRunning)
                }
            }
        }
    }
}
