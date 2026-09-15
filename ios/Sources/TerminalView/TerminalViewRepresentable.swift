import SwiftUI
import UIKit

/// SwiftUI wrapper around the UIKit terminal grid.
struct TerminalViewRepresentable: UIViewRepresentable {
    @ObservedObject var session: TerminalSession
    /// Asked when a paste looks like it could inject a command.
    var onUnsafePaste: ((String, @escaping (Bool) -> Void) -> Void)?
    /// Set to true to make the terminal take the keyboard when it appears.
    var focusOnAppear: Bool = true
    /// Whether to show the accessory key bar (Settings ▸ Input).
    var keyBarEnabled: Bool = true

    func makeUIView(context: Context) -> TerminalUIView {
        let view = TerminalUIView(frame: .zero)
        view.session = session
        view.onUnsafePaste = onUnsafePaste
        view.keyBarEnabled = keyBarEnabled
        view.onFontSizeChanged = { size in
            // Keep the observable in step so the settings screen and any other
            // view of this session agree with what the pinch just did.
            session.fontSize = size
        }
        if focusOnAppear {
            DispatchQueue.main.async { _ = view.becomeFirstResponder() }
        }
        return view
    }

    func updateUIView(_ view: TerminalUIView, context: Context) {
        if view.session !== session {
            view.session = session
        }
        view.onUnsafePaste = onUnsafePaste
        view.keyBarEnabled = keyBarEnabled
        if abs(view.fontSet.size - session.fontSize) > 0.01 {
            view.setFontSize(session.fontSize)
        }
    }
}

/// A terminal plus its status bar — what the sessions tab shows.
struct TerminalScreen: View {
    @ObservedObject var session: TerminalSession
    @EnvironmentObject private var settings: AppSettings
    @State private var unsafePaste: UnsafePastePrompt?

    var body: some View {
        VStack(spacing: 0) {
            TerminalViewRepresentable(
                session: session,
                onUnsafePaste: settings.confirmUnsafePaste
                    ? { text, respond in unsafePaste = UnsafePastePrompt(text: text, respond: respond) }
                    : nil,
                keyBarEnabled: settings.keyBarEnabled
            )
            .ignoresSafeArea(.container, edges: .bottom)

            statusBar
        }
        .background(Color(session.theme.background.cgColor))
        .navigationTitle(session.title)
        .navigationBarTitleDisplayMode(.inline)
        .alert("Paste contains newlines", isPresented: .init(
            get: { unsafePaste != nil },
            set: { if !$0 { unsafePaste = nil } }
        ), presenting: unsafePaste) { prompt in
            Button("Cancel", role: .cancel) { prompt.respond(false) }
            Button("Paste anyway", role: .destructive) { prompt.respond(true) }
        } message: { _ in
            Text("The clipboard contains a line break, so pasting it will run the command as soon as it lands.")
        }
    }

    private var statusBar: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
            Text(session.statusLabel)
                .font(.caption.monospaced())
                .lineLimit(1)
            Spacer()
            Text("\(session.cols)×\(session.rows)")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
    }

    private var statusColor: Color {
        if session.isError { return .red }
        return session.isConnected ? .green : .orange
    }
}

/// Carries the pending unsafe-paste decision back to the view that asked.
private struct UnsafePastePrompt: Identifiable {
    let id = UUID()
    let text: String
    let respond: (Bool) -> Void
}
