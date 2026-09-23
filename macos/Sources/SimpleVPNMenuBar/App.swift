// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import SimpleVPNCore

private let bundledCLI = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/simplevpn")

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
  private var item: NSStatusItem!
  private var controller: MenuController!
  private var timer: Timer?

  func applicationDidFinishLaunching(_ notification: Notification) {
    controller = MenuController(
      client: CLIClient(executable: bundledCLI, authorizationExecutable: Bundle.main.executableURL!)
    )
    controller.onChange = { [weak self] in self?.render() }
    controller.onError = { [weak self] message in self?.showError(message) }
    item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    item.button?.setAccessibilityLabel("SimpleVPN")
    let menu = NSMenu()
    menu.delegate = self
    menu.autoenablesItems = false
    item.menu = menu
    render()
    Task { await controller.start() }
    timer = Timer(timeInterval: 5, repeats: true) { [weak self] _ in
      Task { @MainActor in self?.refresh() }
    }
    RunLoop.main.add(timer!, forMode: .common)
  }

  func menuWillOpen(_ menu: NSMenu) { refresh() }

  func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    guard controller?.rows.contains(where: \.isActive) == true else { return .terminateNow }

    sender.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = "Quit SimpleVPN?"
    alert.informativeText =
      "Active VPN connections will remain connected after you quit. "
      + "To disconnect them, choose Cancel, then Disconnect All."
    alert.alertStyle = .warning
    alert.addButton(withTitle: "Quit SimpleVPN")
    alert.addButton(withTitle: "Cancel")
    return alert.runModal() == .alertFirstButtonReturn ? .terminateNow : .terminateCancel
  }

  private func refresh() {
    Task { await controller.refresh() }
  }

  private func render() {
    let unavailable = controller.statusError != nil || controller.status?.recoveryPending == true
    let symbol =
      unavailable
      ? "exclamationmark.shield"
      : controller.rows.contains(where: \.isActive) ? "lock.shield.fill" : "lock.shield"
    let image = NSImage(systemSymbolName: symbol, accessibilityDescription: "SimpleVPN")
    image?.isTemplate = true
    item.button?.image = image
    item.button?.toolTip = "SimpleVPN — \(controller.summary)"
    guard let menu = item.menu else { return }
    menu.removeAllItems()
    add(controller.summary, to: menu)
    if let error = controller.statusError {
      let entry = add("Status error — click for details…", action: #selector(statusError), to: menu)
      entry.representedObject = error
    }
    if let error = controller.discoveryError {
      let entry = add(
        "Cannot list profiles — click for details…", action: #selector(statusError), to: menu)
      entry.representedObject = error
    }
    menu.addItem(.separator())
    if controller.rows.isEmpty {
      add("No profiles found", to: menu)
      add("Add .toml files to ~/.config/simplevpn", to: menu)
    }
    for row in controller.rows {
      let entry = add(row.title, action: #selector(toggle(_:)), to: menu)
      entry.representedObject = row.name
      entry.state = row.isActive && !unavailable ? .on : .off
      entry.isEnabled = controller.canToggle
      entry.toolTip = row.isActive ? "Disconnect \(row.name)" : "Connect \(row.name)"
    }
    menu.addItem(.separator())
    add("Disconnect All", action: #selector(disconnectAll), to: menu)
      .isEnabled = controller.canDisconnectAll
    menu.addItem(.separator())
    let quit = add("Quit SimpleVPN", action: #selector(quit), to: menu)
    quit.keyEquivalent = "q"
    quit.toolTip = "VPN connections will remain active"
  }

  @discardableResult
  private func add(_ title: String, action: Selector? = nil, to menu: NSMenu) -> NSMenuItem {
    let entry = NSMenuItem(title: title, action: action, keyEquivalent: "")
    entry.target = self
    entry.isEnabled = action != nil
    menu.addItem(entry)
    return entry
  }

  @objc private func toggle(_ sender: NSMenuItem) {
    guard let name = sender.representedObject as? String else { return }
    Task { await controller.toggle(name) }
  }

  @objc private func disconnectAll() {
    Task { await controller.disconnectAll() }
  }

  @objc private func statusError(_ sender: NSMenuItem) {
    if let message = sender.representedObject as? String { showError(message) }
  }

  private func showError(_ message: String) {
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = "SimpleVPN"
    alert.informativeText = message
    alert.alertStyle = .warning
    alert.addButton(withTitle: "OK")
    alert.runModal()
  }

  @objc private func quit() { NSApp.terminate(nil) }
}

@main
enum SimpleVPNMenuBar {
  static func main() {
    if CommandLine.arguments.dropFirst().first == AuthorizationHelper.argument {
      let result = AuthorizationHelper.run(
        executable: bundledCLI, uid: getuid(), arguments: Array(CommandLine.arguments.dropFirst(2)))
      FileHandle.standardOutput.write(result.stdout)
      FileHandle.standardError.write(result.stderr)
      exit(result.code)
    }
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    withExtendedLifetime(delegate) { app.run() }
  }
}
