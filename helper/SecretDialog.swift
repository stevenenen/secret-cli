// A window that shows a value to the person in front of the Mac and to nobody
// else. Built by install.sh into libexec/secret-dialog and used by `secret show`.
//
// Two protections, and the second matters more than the first:
//
//   sharingType = .none    excludes the window from screencapture, Screenshot,
//                          QuickTime and screen sharing. macOS enforces it.
//   accessibility off      keeps the text out of the accessibility tree, which
//                          is how an agent on this machine would otherwise read
//                          a window without taking a screenshot at all.
//
// Neither stops a camera pointed at the screen. Nothing can.
//
// The value arrives on stdin, never as an argument, so it is not in the process
// table. Only the key name is passed as an argument, and a key name is not secret.

import AppKit

let args = CommandLine.arguments.dropFirst()
let selfTest = args.contains("--self-test")
let key = args.first(where: { !$0.hasPrefix("--") }) ?? "secret"

let timeout: Double = {
    guard let i = args.firstIndex(of: "--timeout"),
          let next = args.dropFirst(args.distance(from: args.startIndex, to: i) + 1).first,
          let seconds = Double(next) else { return 120 }
    return seconds
}()

let value: String = selfTest
    ? "self-test"
    : (String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8) ?? "")

final class Hidden: NSTextField {
    // Belt and braces: a view can be asked for its accessibility attributes in
    // more than one way, so refuse at the source as well as via the flag.
    override func isAccessibilityElement() -> Bool { false }
    override func accessibilityRole() -> NSAccessibility.Role? { .unknown }
    override func accessibilityValue() -> String? { nil }
    override func accessibilityLabel() -> String? { nil }
    override func accessibilityTitle() -> String? { nil }
    override func accessibilityChildren() -> [Any]? { nil }
}

let app = NSApplication.shared
app.setActivationPolicy(.regular)

let label = Hidden(labelWithString: value)
label.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
label.isSelectable = false
label.maximumNumberOfLines = 0
label.lineBreakMode = .byCharWrapping
label.preferredMaxLayoutWidth = 460
label.setAccessibilityElement(false)
label.translatesAutoresizingMaskIntoConstraints = false

let caption = NSTextField(labelWithString: "Not capturable: screenshots and screen recordings will not show this.")
caption.font = NSFont.systemFont(ofSize: 11)
caption.textColor = .secondaryLabelColor
caption.maximumNumberOfLines = 0
caption.preferredMaxLayoutWidth = 460
caption.translatesAutoresizingMaskIntoConstraints = false

final class Closer: NSObject {
    @objc func done() { NSApp.terminate(nil) }
}
let closer = Closer()

let button = NSButton(title: "Done", target: closer, action: #selector(Closer.done))
button.keyEquivalent = "\r"
button.translatesAutoresizingMaskIntoConstraints = false

let content = NSView()
content.addSubview(label)
content.addSubview(caption)
content.addSubview(button)

NSLayoutConstraint.activate([
    label.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
    label.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
    label.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),

    caption.topAnchor.constraint(equalTo: label.bottomAnchor, constant: 16),
    caption.leadingAnchor.constraint(equalTo: label.leadingAnchor),
    caption.trailingAnchor.constraint(equalTo: label.trailingAnchor),

    button.topAnchor.constraint(equalTo: caption.bottomAnchor, constant: 16),
    button.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
    button.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),
])

let window = NSWindow(
    contentRect: NSRect(x: 0, y: 0, width: 500, height: 160),
    styleMask: [.titled, .closable],
    backing: .buffered,
    defer: false
)
window.title = "secret: \(key)"
window.contentView = content
window.center()

// The whole point.
window.sharingType = .none
window.setAccessibilityElement(false)
content.setAccessibilityElement(false)

if selfTest {
    var problems: [String] = []
    if window.sharingType != .none { problems.append("sharingType is not .none") }
    if label.isAccessibilityElement() { problems.append("label is an accessibility element") }
    if window.isAccessibilityElement() { problems.append("window is an accessibility element") }
    if problems.isEmpty {
        print("ok")
        exit(0)
    }
    for problem in problems { FileHandle.standardError.write(Data((problem + "\n").utf8)) }
    exit(1)
}

window.makeKeyAndOrderFront(nil)
app.activate(ignoringOtherApps: true)

if timeout > 0 {
    DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { NSApp.terminate(nil) }
}

app.run()
