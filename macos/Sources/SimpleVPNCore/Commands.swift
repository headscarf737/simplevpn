// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

public struct CommandOutput: Sendable {
  public let code: Int32
  public let stdout: Data
  public let stderr: Data

  public init(code: Int32, stdout: Data = Data(), stderr: Data = Data()) {
    self.code = code
    self.stdout = stdout
    self.stderr = stderr
  }
}

public protocol CommandRunning: Sendable {
  func run(executable: URL, arguments: [String], timeout: Duration) async throws -> CommandOutput
}

public enum VPNAction: Sendable, Equatable {
  case connect(URL)
  case disconnect(String)
  case disconnectAll
}

public enum ClientError: LocalizedError {
  case cancelled
  case timedOut
  case command(String)

  public var errorDescription: String? {
    switch self {
    case .cancelled: "Authorization cancelled."
    case .timedOut:
      "VPN command timed out. The operation may still complete; check VPN status before retrying."
    case .command(let message): message
    }
  }
}

public protocol VPNClient: Sendable {
  func startSession() async throws
  func status() async throws -> VPNStatus
  func perform(_ action: VPNAction) async throws
}

public struct CLIClient: VPNClient {
  public let executable: URL
  public let authorizationExecutable: URL
  public let runner: any CommandRunning
  public let session: AppSession

  public init(
    executable: URL, authorizationExecutable: URL, runner: any CommandRunning = ProcessRunner(),
    session: AppSession = AppSession()
  ) {
    self.executable = executable
    self.authorizationExecutable = authorizationExecutable
    self.runner = runner
    self.session = session
  }

  public func startSession() async throws {
    try await session.ensure { try await authorize() }
  }

  public func status() async throws -> VPNStatus {
    let result = try await runner.run(
      executable: executable, arguments: ["status", "--json"], timeout: .seconds(15))
    try check(result)
    do { return try JSONDecoder().decode(VPNStatus.self, from: result.stdout) } catch {
      throw ClientError.command("Cannot read VPN status: invalid response from simplevpn.")
    }
  }

  public func perform(_ action: VPNAction) async throws {
    try await startSession()
    let actionArguments = switch action {
    case .connect(let file): ["up", "--", file.path]
    case .disconnect(let name): ["down", "--", name]
    case .disconnectAll: ["down", "--all"]
    }
    let arguments = ["--no-elevate"] + actionArguments
    // Exit 5 means no request was dispatched. Re-establish the app session if
    // the supervisor stopped; other failures must never replay the action.
    let direct = try await runner.run(
      executable: executable, arguments: arguments, timeout: .seconds(180))
    guard direct.code == 5 else {
      try check(direct)
      return
    }
    try Task.checkCancellation()
    try await startSession()
    try check(
      try await runner.run(
        executable: executable, arguments: arguments, timeout: .seconds(180)))
  }

  private func authorize() async throws {
    let result = try await runner.run(
      executable: authorizationExecutable,
      arguments: [AuthorizationHelper.argument, "__authorize-app"],
      timeout: .seconds(180)
    )
    if result.code == 0,
      String(decoding: result.stdout, as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines) == "SIMPLEVPN_AUTH_CANCELLED"
    {
      throw ClientError.cancelled
    }
    try check(result)
  }

  private func check(_ result: CommandOutput) throws {
    guard result.code == 0 else {
      let message = String(decoding: result.stderr, as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
      throw ClientError.command(message.isEmpty ? "Command failed (\(result.code))." : message)
    }
  }
}
