import SwiftUI

struct KnownHostsView: View {
    @EnvironmentObject private var vault: Vault
    @State private var pendingForget: KnownHost?

    var body: some View {
        Group {
            if vault.knownHosts.isEmpty {
                ContentUnavailableView(
                    "No pinned hosts",
                    systemImage: "lock.shield",
                    description: Text("The first time you connect to a host, its key is shown for you to accept and is then pinned here.")
                )
            } else {
                List {
                    ForEach(vault.knownHosts.sorted { $0.hostname < $1.hostname }) { entry in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(entry.id).font(.body.monospaced())
                            Text(entry.keyType)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            Text(entry.fingerprint)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Text("first seen \(entry.firstSeen.formatted(date: .abbreviated, time: .shortened))")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                        .padding(.vertical, 2)
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) { pendingForget = entry } label: {
                                Label("Forget", systemImage: "trash")
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Known hosts")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Forget this host key?", isPresented: .init(
            get: { pendingForget != nil },
            set: { if !$0 { pendingForget = nil } }
        ), presenting: pendingForget) { entry in
            Button("Cancel", role: .cancel) {}
            Button("Forget", role: .destructive) { vault.forget(entry) }
        } message: { entry in
            Text("The next connection to \(entry.id) will be treated as a first connection and you will be asked to trust its key again.")
        }
    }
}
