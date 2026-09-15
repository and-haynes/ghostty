import SwiftUI
import UIKit

/// The accessory key bar: `[fixed left] | [scrolling middle] | [fixed right]`.
///
/// iOS's keyboard has no Esc, Ctrl, Tab or arrows, which between them are most
/// of what a terminal needs. The layout keeps the keys you reach for without
/// looking — Esc, Tab, Ctrl, Alt on the left; paste and the keyboard toggle on
/// the right — pinned in place, and lets everything else scroll between them,
/// so muscle memory survives a scroll position.
struct KeyBarView: View {
    @ObservedObject var model: KeyBarModel

    static let height: CGFloat = 44

    var body: some View {
        HStack(spacing: 0) {
            HStack(spacing: 2) {
                key("Esc", label: "esc") { model.perform(.escape) }
                key("Tab", symbol: "arrow.right.to.line") { model.perform(.tab) }
                ForEach(KeyBarModel.Modifier.allCases) { modifier in
                    ModifierKey(model: model, modifier: modifier)
                }
            }
            .padding(.leading, 6)

            divider.padding(.horizontal, 4)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ArrowCluster(model: model)

                    group {
                        ForEach(["-", "/", "|", "~", ":", ";", "'", "\""], id: \.self) { symbol in
                            key(Self.name(for: symbol), label: symbol) {
                                model.perform(.literal(symbol))
                            }
                        }
                    }

                    group {
                        key("Home", symbol: "arrow.left.to.line.compact") { model.perform(.home) }
                        key("End", symbol: "arrow.right.to.line.compact") { model.perform(.end) }
                        key("Page up", symbol: "arrow.up.to.line.compact") { model.perform(.pageUp) }
                        key("Page down", symbol: "arrow.down.to.line.compact") { model.perform(.pageDown) }
                    }

                    Button {
                        Haptics.shared.fire(.functionRowToggle)
                        withAnimation(.snappy(duration: 0.15)) { model.showsFunctionKeys.toggle() }
                    } label: {
                        Text("Fn")
                            .font(.system(size: 15, design: .rounded).weight(.medium))
                            .frame(minWidth: 40, minHeight: 32)
                            .background(
                                model.showsFunctionKeys ? Color.accentColor.opacity(0.22) : .clear,
                                in: RoundedRectangle(cornerRadius: 8)
                            )
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(model.showsFunctionKeys ? AnyShapeStyle(.tint) : AnyShapeStyle(.primary))
                    .accessibilityLabel("Function keys")
                    .accessibilityAddTraits(model.showsFunctionKeys ? .isSelected : [])

                    if model.showsFunctionKeys {
                        group {
                            ForEach(1...12, id: \.self) { index in
                                key("F\(index)", label: "F\(index)") { model.perform(.function(index)) }
                            }
                        }
                        .transition(.opacity.combined(with: .move(edge: .leading)))
                    }
                }
                .padding(.horizontal, 4)
            }

            divider.padding(.horizontal, 4)

            HStack(spacing: 2) {
                key("Paste", symbol: "doc.on.clipboard") { model.perform(.paste) }
                Button { model.perform(.hideKeyboard) } label: {
                    Image(systemName: "keyboard.chevron.compact.down")
                        .font(.system(size: 16, weight: .medium))
                        .frame(minWidth: 40, minHeight: 32)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(.tint)
                .accessibilityLabel("Hide keyboard")
            }
            .padding(.trailing, 6)
        }
        .frame(height: Self.height)
    }

    private var divider: some View {
        Rectangle().fill(.quaternary).frame(width: 1, height: 22)
    }

    /// A visually grouped run of keys, so related symbols read as one block
    /// rather than an undifferentiated row of boxes.
    @ViewBuilder
    private func group<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        HStack(spacing: 2) { content() }
            .padding(2)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder
    private func key(
        _ name: String,
        label: String? = nil,
        symbol: String? = nil,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Group {
                if let symbol {
                    Image(systemName: symbol)
                } else {
                    Text(label ?? name)
                }
            }
            .font(.system(size: 15, design: .rounded))
            // 40x32 visually, but the tappable area is the full bar height:
            // these are thumb targets on a moving train.
            .frame(minWidth: 40, minHeight: 32)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(name)
    }

    private static func name(for symbol: String) -> String {
        switch symbol {
        case "-": return "Hyphen"
        case "/": return "Slash"
        case "|": return "Pipe"
        case "~": return "Tilde"
        case ":": return "Colon"
        case ";": return "Semicolon"
        case "'": return "Apostrophe"
        case "\"": return "Quote"
        default: return symbol
        }
    }
}

/// A modifier with off / sticky / locked appearance.
private struct ModifierKey: View {
    @ObservedObject var model: KeyBarModel
    let modifier: KeyBarModel.Modifier

    var body: some View {
        let state = model.state(of: modifier)
        Button { model.tap(modifier) } label: {
            Text(modifier.label)
                .font(.system(size: 15, design: .rounded))
                .frame(minWidth: 44, minHeight: 32)
                .background(
                    state == .off ? Color.clear : Color.accentColor.opacity(state == .locked ? 0.34 : 0.2),
                    in: RoundedRectangle(cornerRadius: 8)
                )
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(state == .off ? AnyShapeStyle(.primary) : AnyShapeStyle(.tint))
        .overlay(alignment: .topTrailing) {
            if state == .locked {
                Image(systemName: "lock.fill")
                    .font(.system(size: 8))
                    .padding(2)
                    .foregroundStyle(.tint)
            }
        }
        .accessibilityLabel(modifier.label)
        .accessibilityValue(state == .off ? "off" : state == .sticky ? "armed" : "locked")
        .animation(.snappy(duration: 0.15), value: state)
    }
}

/// ← ↑ ↓ → as one block, with press-and-hold auto-repeat.
private struct ArrowCluster: View {
    @ObservedObject var model: KeyBarModel

    var body: some View {
        HStack(spacing: 2) {
            RepeatKey(symbol: "arrow.left", name: "Left arrow") { model.perform(.left) }
            RepeatKey(symbol: "arrow.up", name: "Up arrow") { model.perform(.up) }
            RepeatKey(symbol: "arrow.down", name: "Down arrow") { model.perform(.down) }
            RepeatKey(symbol: "arrow.right", name: "Right arrow") { model.perform(.right) }
        }
        .padding(2)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
    }
}

/// Fires once on tap, repeats while held.
private struct RepeatKey: View {
    let symbol: String
    let name: String
    let action: @MainActor () -> Void

    @State private var repeater: Task<Void, Never>?
    @State private var pressed = false

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 15, weight: .medium))
            .frame(minWidth: 40, minHeight: 32)
            .background(pressed ? Color.accentColor.opacity(0.25) : .clear, in: RoundedRectangle(cornerRadius: 8))
            .contentShape(Rectangle())
            .onTapGesture { action() }
            .onAppear { Haptics.shared.prepare(for: .arrowRepeat) }
            // maximumDistance matters: a finger that starts on an arrow and
            // swipes should scroll the bar, not get stuck auto-repeating.
            .onLongPressGesture(minimumDuration: 0.3, maximumDistance: 12) {
                action()
                repeater?.cancel()
                repeater = Task { @MainActor in
                    while !Task.isCancelled {
                        try? await Task.sleep(for: .milliseconds(60))
                        guard !Task.isCancelled else { break }
                        action()
                    }
                }
            } onPressingChanged: { pressing in
                pressed = pressing
                if !pressing {
                    repeater?.cancel()
                    repeater = nil
                }
            }
            .accessibilityLabel(name)
    }
}

/// Hosts the SwiftUI bar as a `UIInputView` so it can be the terminal's
/// `inputAccessoryView` and pick up the keyboard's own material.
@MainActor
final class KeyBarHost: UIInputView {
    let model: KeyBarModel
    private let hosting: UIHostingController<KeyBarView>

    init(model: KeyBarModel) {
        self.model = model
        hosting = UIHostingController(rootView: KeyBarView(model: model))
        super.init(
            frame: CGRect(x: 0, y: 0, width: 320, height: KeyBarView.height),
            inputViewStyle: .keyboard
        )
        hosting.view.backgroundColor = .clear
        // Without this the hosting controller reserves the keyboard's safe-area
        // inset below the bar — a dead gap between the bar and the keys.
        hosting.safeAreaRegions = []
        hosting.view.translatesAutoresizingMaskIntoConstraints = false
        addSubview(hosting.view)
        NSLayoutConstraint.activate([
            hosting.view.leadingAnchor.constraint(equalTo: leadingAnchor),
            hosting.view.trailingAnchor.constraint(equalTo: trailingAnchor),
            hosting.view.topAnchor.constraint(equalTo: topAnchor),
            hosting.view.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
        allowsSelfSizing = true
        autoresizingMask = .flexibleWidth
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    override var intrinsicContentSize: CGSize {
        CGSize(width: UIView.noIntrinsicMetric, height: KeyBarView.height)
    }
}
