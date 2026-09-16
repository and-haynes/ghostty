import SwiftUI

/// The **Test connection** sheet.
///
/// A phone gives you nowhere to run `ssh -vvv`, so when a connection fails the
/// only thing a person has to go on is whatever the app chose to say. This is
/// the screen that says everything: whether the host answered, what it claims
/// to be, which algorithms it offers, which of those we can actually use, the
/// host key fingerprint, and — only when that key is already trusted — whether
/// the credentials on file are accepted.
///
/// Nothing here opens a shell or runs a command on the far end.
struct ConnectionTestView: View {
    @EnvironmentObject private var vault: Vault
    @EnvironmentObject private var settings: AppSettings
    @Environment(\.dismiss) private var dismiss

    let host: Host

    @State private var report: SSHConnectionReport?
    @State private var isRunning = false
    @State private var failure: String?

    var body: some View {
        NavigationStack {
            Form {
                if isRunning {
                    Section {
                        HStack(spacing: 12) {
                            ProgressView()
                            Text("Testing \(host.username)@\(host.destination)…")
                                .foregroundStyle(.secondary)
                        }
                    }
                } else if let report {
                    resultSections(report)
                } else if let failure {
                    Section {
                        Text(failure).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Test connection")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Run again") { Task { await run() } }
                        .disabled(isRunning)
                }
            }
            .task { await run() }
        }
    }

    @ViewBuilder
    private func resultSections(_ report: SSHConnectionReport) -> some View {
        Section {
            Label {
                Text(report.headline)
            } icon: {
                Image(systemName: report.succeeded ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(report.succeeded ? .green : .orange)
            }
        }

        if let offer = report.offer {
            Section("The server says it is") {
                Text(offer.banner)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                ForEach(offer.preamble, id: \.self) { line in
                    Text(line).font(.caption).foregroundStyle(.secondary)
                }
            }
        }

        if let kex = report.negotiatedKeyExchange {
            Section("Would negotiate") {
                algorithmRow("Key exchange", kex)
                algorithmRow("Host key", report.negotiatedHostKeyAlgorithm)
                algorithmRow("Cipher", report.negotiatedCipher)
                algorithmRow("MAC", report.negotiatedMAC ?? "the cipher's own")
            }
        }

        if let fingerprint = report.hostKeyFingerprint {
            Section {
                Text(report.hostKeyType ?? "host key")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(fingerprint)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            } header: {
                Text("Host key")
            } footer: {
                switch report.hostKeyMatchesPin {
                case .some(true):
                    Text("Matches the key saved for this host.")
                case .some(false):
                    Text("Does NOT match the key saved for this host.").foregroundStyle(.red)
                case nil:
                    Text(
                        """
                        Not saved yet, so no password or key was sent. Connect once, \
                        check this fingerprint against the server, and trust it.
                        """
                    )
                }
            }
        }

        if let offer = report.offer {
            Section("What it offers") {
                algorithmList("Host keys", offer.hostKeyAlgorithms)
                algorithmList("Ciphers", offer.ciphers)
                algorithmList("Key exchange", offer.keyExchangeAlgorithms)
                algorithmList("MACs", offer.macs)
            }
            Section("What Ghostty offers") {
                // What it *offers*, not everything it could verify: the
                // certificate algorithms are only named when a CA is
                // configured, and a sheet that listed them anyway would be
                // diagnosing a negotiation the app will never attempt.
                algorithmList(
                    "Host keys",
                    SSHAlgorithmSupport.offeredHostKeyAlgorithms(
                        trustingCertificateAuthorities: !settings.trustedAuthorities.isEmpty
                    )
                )
                algorithmList("Ciphers", SSHAlgorithmSupport.ciphers)
                algorithmList("Key exchange", SSHAlgorithmSupport.keyExchangeAlgorithms)
                algorithmList("MACs", SSHAlgorithmSupport.macs)
            }
        }

        if let mismatch = report.mismatch, !mismatch.canNegotiate {
            Section("What is missing") {
                ForEach(mismatch.advice, id: \.self) { note in
                    Text(note).font(.callout)
                }
            }
        }

        Section {
            Button {
                UIPasteboard.general.string = report.detail
                Haptics.shared.fire(.copyConfirmed)
            } label: {
                Label("Copy the whole report", systemImage: "doc.on.doc")
            }
        }
    }

    private func algorithmRow(_ label: String, _ value: String?) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(value ?? "—")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
        }
    }

    private func algorithmList(_ label: String, _ values: [String]) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(values.isEmpty ? "(none)" : values.joined(separator: ", "))
                .font(.caption2.monospaced())
                .textSelection(.enabled)
        }
        .padding(.vertical, 2)
    }

    @MainActor
    private func run() async {
        guard !isRunning else { return }
        isRunning = true
        failure = nil
        defer { isRunning = false }

        do {
            // The same plan a real connection would use, minus the interactive
            // password prompt: a diagnostic must not start asking for secrets.
            let plan = try await SSHConnectionCoordinator.plan(
                for: host,
                identity: vault.identity(withID: host.identityID),
                vault: vault,
                cols: 80,
                rows: 24
            )
            report = await SSHConnectionTester.run(
                request: plan.request,
                auth: plan.authMethods,
                vault: vault,
                trustedHostAuthorities: settings.trustedAuthorities.keys
            )
        } catch let error as SSHError where error == .noAuthenticationMethods {
            // Still worth testing: reachability and the algorithm comparison do
            // not need a credential, and they are what usually went wrong.
            report = await SSHConnectionTester.run(
                request: SSHConnectionRequest(
                    hostname: host.hostname,
                    port: host.port,
                    username: host.username
                ),
                auth: [],
                vault: vault,
                trustedHostAuthorities: settings.trustedAuthorities.keys
            )
        } catch {
            failure = error.localizedDescription
        }
        Haptics.shared.fire(report?.succeeded == true ? .syncSucceeded : .syncFailed)
    }
}
