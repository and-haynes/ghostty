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
    /// Reports how much of the window's bottom edge the keyboard and key bar
    /// cover, so the owner can inset for it. See `TerminalScreen`.
    var onKeyboardOverlapChanged: ((CGFloat) -> Void)?

    func makeUIView(context: Context) -> TerminalUIView {
        let view = TerminalUIView(frame: .zero)
        view.session = session
        view.onUnsafePaste = onUnsafePaste
        view.keyBarEnabled = keyBarEnabled
        view.onKeyboardOverlapChanged = onKeyboardOverlapChanged
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
        view.onKeyboardOverlapChanged = onKeyboardOverlapChanged
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
    /// Measured by the terminal view from the real keyboard frame. See the
    /// comment in `body` for why SwiftUI's own number is not good enough.
    @State private var keyboardOverlap: CGFloat = 0

    var body: some View {
        // Layout, because it is the thing #008A2 was about. The key bar is the
        // terminal's `inputAccessoryView`, so UIKit hangs it off the keyboard
        // and its height is part of the keyboard frame SwiftUI insets for. That
        // only helps if this stack actually stays inside the safe area.
        //
        // It used to not: `ignoresSafeArea(.container, edges: .bottom)` on the
        // terminal grew it into the bottom inset, which pushed the status line
        // down into the row the key bar occupies, and the two drew on top of
        // each other. The background bleeds instead — it has no content to
        // lose — and the stack itself is laid out honestly, which keeps the
        // status line above the key bar in every keyboard state (hidden, shown,
        // floating on iPad, hardware keyboard attached) and in both
        // orientations, with no fixed offsets anywhere.
        VStack(spacing: 0) {
            TerminalViewRepresentable(
                session: session,
                onUnsafePaste: settings.confirmUnsafePaste
                    ? { text, respond in unsafePaste = UnsafePastePrompt(text: text, respond: respond) }
                    : nil,
                keyBarEnabled: settings.keyBarEnabled,
                onKeyboardOverlapChanged: { overlap in
                    guard abs(overlap - keyboardOverlap) > 0.5 else { return }
                    keyboardOverlap = overlap
                }
            )

            statusBar
        }
        .padding(.bottom, keyboardOverlap)
        // SwiftUI's own keyboard avoidance is switched off here on purpose. It
        // under-insets when the first responder has an `inputAccessoryView` —
        // in landscape by about the accessory's own height — which put the
        // status line underneath the key bar and made both unreadable (#008A2).
        // The padding above comes from the real keyboard frame, which UIKit
        // reports with the accessory included, so the key bar is always the
        // sole occupant of the row above the keyboard: hidden, shown, floating
        // on iPad, or with a hardware keyboard attached, in both orientations.
        .ignoresSafeArea(.keyboard, edges: .bottom)
        .background(Color(session.theme.background.cgColor).ignoresSafeArea())
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
        .frame(maxWidth: .infinity)
        .background(.bar)
        // Named so a UI test can assert where it sits relative to the key bar
        // rather than guessing at its text.
        .accessibilityIdentifier("session-status-bar")
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
