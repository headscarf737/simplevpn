// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

public enum AuthorizationHelper {
  public static let argument = "--authorize-vpn"

  // Run inside a child of SimpleVPN.app so macOS identifies SimpleVPN as the
  // requester. The parent can still time out or cancel this blocking operation.
  @MainActor
  public static func run(executable: URL, uid: UInt32, arguments: [String]) -> CommandOutput {
    // This entry point only starts/authorizes the bundled supervisor. The app
    // supplies the executable and real UID itself, never from command-line input.
    guard arguments == ["__authorize-app"] else {
      return CommandOutput(code: 1, stderr: Data("Invalid VPN authorization request.\n".utf8))
    }
    // __authorize-app always grants control to the invoking account.
    let command = shellCommand(
      [executable.path, "--invoking-uid", String(uid)] + arguments)
    return execute(script: script, arguments: [command])
  }

  // Single quotes protect every shell argument, including paths containing quotes.
  static func shellCommand(_ arguments: [String]) -> String {
    arguments.map { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }
      .joined(separator: " ")
  }

  // Program text is fixed. The quoted command is an Apple event argument, never
  // script source. Cancellation stays distinct from CLI errors.
  static let script = """
    on run argv
        try
            do shell script (item 1 of argv) with administrator privileges
        on error messageText number errorNumber
            if errorNumber is -128 then return "SIMPLEVPN_AUTH_CANCELLED"
            error messageText number errorNumber
        end try
    end run
    """

  @MainActor
  static func execute(script source: String, arguments: [String]) -> CommandOutput {
    guard let script = NSAppleScript(source: source) else {
      return CommandOutput(code: 1, stderr: Data("Cannot create authorization script.\n".utf8))
    }
    let argv = NSAppleEventDescriptor.list()
    for (index, value) in arguments.enumerated() {
      argv.insert(NSAppleEventDescriptor(string: value), at: index + 1)
    }
    let event = NSAppleEventDescriptor(
      eventClass: AEEventClass(kCoreEventClass), eventID: AEEventID(kAEOpenApplication),
      targetDescriptor: NSAppleEventDescriptor.currentProcess(),
      returnID: AEReturnID(kAutoGenerateReturnID),
      transactionID: AETransactionID(kAnyTransactionID))
    event.setParam(argv, forKeyword: AEKeyword(keyDirectObject))

    var error: NSDictionary?
    let result = script.executeAppleEvent(event, error: &error)
    if let error {
      let message = error[NSAppleScript.errorMessage] as? String ?? "Authorization script failed."
      return CommandOutput(code: 1, stderr: Data((message + "\n").utf8))
    }
    let output = result.stringValue.map { $0 + "\n" } ?? ""
    return CommandOutput(code: 0, stdout: Data(output.utf8))
  }
}
