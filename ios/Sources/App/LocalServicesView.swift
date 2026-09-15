import SwiftUI

/// Non-SSH things found on the LAN: web UIs, shares, screens.
///
/// Deliberately a reference list rather than a launcher with opinions — the
/// app cannot speak SMB or RDP, and pretending otherwise would be worse than
/// showing an address you can copy.
struct LocalServicesView: View {
    @EnvironmentObject private var vault: Vault
    @State private var renaming: LocalService?
    @State private var newAlias = ""

    var body: some View {
        List {
            ForEach(vault.localServices) { service in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(service.alias).font(.body.weight(.medium))
                        Spacer()
                        Text(service.serviceType)
                            .font(.caption2)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Color.accentColor.opacity(0.18), in: Capsule())
                    }
                    Text(service.urlString).font(.caption.monospaced()).foregroundStyle(.secondary)
                    Text("seen \(service.lastSeen.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
                .padding(.vertical, 2)
                .swipeActions(edge: .trailing) {
                    Button(role: .destructive) {
                        Haptics.shared.fire(.listAction)
                        vault.deleteLocalService(service)
                    } label: { Label("Delete", systemImage: "trash") }
                    Button {
                        renaming = service
                        newAlias = service.alias
                    } label: { Label("Rename", systemImage: "pencil") }
                        .tint(.blue)
                }
                .contextMenu {
                    if let url = service.url {
                        Link(destination: url) { Label("Open in Safari", systemImage: "safari") }
                    }
                    Button {
                        UIPasteboard.general.string = service.urlString
                    } label: { Label("Copy address", systemImage: "doc.on.doc") }
                }
            }
        }
        .navigationTitle("Local services")
        .navigationBarTitleDisplayMode(.inline)
        .overlay {
            if vault.localServices.isEmpty {
                ContentUnavailableView(
                    "Nothing yet",
                    systemImage: "network",
                    description: Text("Scan the local network to find web UIs and shares.")
                )
            }
        }
        .alert("Rename", isPresented: .init(
            get: { renaming != nil },
            set: { if !$0 { renaming = nil } }
        ), presenting: renaming) { service in
            TextField("Name", text: $newAlias)
            Button("Cancel", role: .cancel) {}
            Button("Save") { vault.renameLocalService(service, to: newAlias) }
        }
    }
}
