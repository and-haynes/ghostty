import UIKit

/// The row of keys above the software keyboard.
///
/// iOS's keyboard has no Esc, no Ctrl, no arrows and no Tab, which between
/// them account for most of what a terminal needs. Ctrl and Alt are *sticky*
/// rather than held: you cannot hold a modifier and tap a letter with one
/// thumb, so tapping Ctrl arms it for exactly the next key.
@MainActor
protocol TerminalKeyBarDelegate: AnyObject {
    func keyBar(_ bar: TerminalKeyBar, didPress action: TerminalKeyBar.Action)
    func keyBarDidChangeStickyMods(_ bar: TerminalKeyBar)
}

@MainActor
final class TerminalKeyBar: UIInputView {
    enum Action: Equatable {
        case escape, tab
        case up, down, left, right
        case home, end, pageUp, pageDown
        case literal(String)
        case paste
        case hideKeyboard
    }

    weak var delegate: TerminalKeyBarDelegate?

    /// Modifiers armed for the next keystroke.
    private(set) var stickyMods: VTMods = [] {
        didSet {
            ctrlButton.isSelected = stickyMods.contains(.ctrl)
            altButton.isSelected = stickyMods.contains(.alt)
            delegate?.keyBarDidChangeStickyMods(self)
        }
    }

    private let scrollView = UIScrollView()
    private let stack = UIStackView()
    private lazy var ctrlButton = makeButton(title: "Ctrl", action: nil, toggles: true)
    private lazy var altButton = makeButton(title: "Alt", action: nil, toggles: true)

    init() {
        super.init(frame: CGRect(x: 0, y: 0, width: 320, height: 46), inputViewStyle: .keyboard)
        autoresizingMask = .flexibleWidth
        build()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    /// Consume the armed modifiers; called after each real keystroke.
    func consumeStickyMods() -> VTMods {
        let mods = stickyMods
        if !mods.isEmpty { stickyMods = [] }
        return mods
    }

    func clearStickyMods() {
        if !stickyMods.isEmpty { stickyMods = [] }
    }

    // MARK: - Construction

    private func build() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.showsHorizontalScrollIndicator = false
        scrollView.alwaysBounceHorizontal = true
        addSubview(scrollView)

        stack.axis = .horizontal
        stack.spacing = 6
        stack.alignment = .fill
        stack.translatesAutoresizingMaskIntoConstraints = false
        scrollView.addSubview(stack)

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: bottomAnchor),
            stack.leadingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.leadingAnchor, constant: 8),
            stack.trailingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.trailingAnchor, constant: -8),
            stack.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor, constant: 5),
            stack.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor, constant: -5),
            stack.heightAnchor.constraint(equalTo: scrollView.frameLayoutGuide.heightAnchor, constant: -10),
        ])

        stack.addArrangedSubview(makeButton(title: "Esc", action: .escape))
        stack.addArrangedSubview(makeButton(title: "Tab", action: .tab))
        stack.addArrangedSubview(ctrlButton)
        stack.addArrangedSubview(altButton)
        stack.addArrangedSubview(makeButton(title: "←", action: .left))
        stack.addArrangedSubview(makeButton(title: "↑", action: .up))
        stack.addArrangedSubview(makeButton(title: "↓", action: .down))
        stack.addArrangedSubview(makeButton(title: "→", action: .right))
        for literal in ["-", "/", "|", "~", ":"] {
            stack.addArrangedSubview(makeButton(title: literal, action: .literal(literal)))
        }
        stack.addArrangedSubview(makeButton(title: "Home", action: .home))
        stack.addArrangedSubview(makeButton(title: "End", action: .end))
        stack.addArrangedSubview(makeButton(title: "PgUp", action: .pageUp))
        stack.addArrangedSubview(makeButton(title: "PgDn", action: .pageDown))
        stack.addArrangedSubview(makeButton(title: "Paste", action: .paste))
        stack.addArrangedSubview(makeButton(title: "⌄", action: .hideKeyboard))

        ctrlButton.addAction(UIAction { [weak self] _ in
            guard let self else { return }
            self.stickyMods.formSymmetricDifference(.ctrl)
        }, for: .touchUpInside)
        altButton.addAction(UIAction { [weak self] _ in
            guard let self else { return }
            self.stickyMods.formSymmetricDifference(.alt)
        }, for: .touchUpInside)
    }

    private func makeButton(title: String, action: Action?, toggles: Bool = false) -> UIButton {
        var config = UIButton.Configuration.gray()
        config.title = title
        config.cornerStyle = .medium
        config.contentInsets = NSDirectionalEdgeInsets(top: 4, leading: 10, bottom: 4, trailing: 10)
        config.baseForegroundColor = .label
        let button = UIButton(configuration: config)
        // Apple's 44pt minimum: these are thumb targets on a moving train.
        button.widthAnchor.constraint(greaterThanOrEqualToConstant: 44).isActive = true
        button.titleLabel?.font = .monospacedSystemFont(ofSize: 15, weight: .medium)
        button.accessibilityLabel = accessibilityName(for: title)

        if toggles {
            button.configurationUpdateHandler = { btn in
                var updated = btn.configuration
                updated?.baseBackgroundColor = btn.isSelected ? .tintColor : nil
                updated?.baseForegroundColor = btn.isSelected ? .black : .label
                btn.configuration = updated
            }
        } else if let action {
            button.addAction(UIAction { [weak self] _ in
                guard let self else { return }
                self.delegate?.keyBar(self, didPress: action)
            }, for: .touchUpInside)
        }
        return button
    }

    private func accessibilityName(for title: String) -> String {
        switch title {
        case "←": return "Left arrow"
        case "→": return "Right arrow"
        case "↑": return "Up arrow"
        case "↓": return "Down arrow"
        case "⌄": return "Hide keyboard"
        case "|": return "Pipe"
        case "~": return "Tilde"
        case ":": return "Colon"
        case "-": return "Hyphen"
        case "/": return "Slash"
        default: return title
        }
    }
}
