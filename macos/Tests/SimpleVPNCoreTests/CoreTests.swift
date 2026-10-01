// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import Testing

@testable import SimpleVPNCore

private func status(_ profiles: [(String, ActiveProfile.State)] = [], recovery: Bool = false)
  -> VPNStatus
{
  VPNStatus(
    profiles: profiles.map { ActiveProfile(name: $0.0, state: $0.1) }, recoveryPending: recovery)
}

private actor RecordingRunner: CommandRunning {
  var requests: [(URL, [String])] = []
  var timeouts: [Duration] = []
  var responses: [CommandOutput]
  init(_ response: CommandOutput) { self.responses = [response] }
  init(responses: [CommandOutput]) { self.responses = responses }
  func run(executable: URL, arguments: [String], timeout: Duration) async throws -> CommandOutput {
    requests.append((executable, arguments))
    timeouts.append(timeout)
    return responses.count > 1 ? responses.removeFirst() : responses[0]
  }
}

private actor Gate {
  private var arrived = false
  private var opened = false
  private var waiting: CheckedContinuation<Void, Never>?
  private var observers: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    arrived = true
    for observer in observers { observer.resume() }
    observers = []
    if !opened { await withCheckedContinuation { waiting = $0 } }
  }
  func waitUntilArrived() async {
    if !arrived { await withCheckedContinuation { observers.append($0) } }
  }
  func open() {
    opened = true
    waiting?.resume()
    waiting = nil
  }
}

private actor StubClient: VPNClient {
  var actions: [VPNAction] = []
  var statusCalls = 0
  var sessionCalls = 0
  let startupError: ClientError?
  var statuses: [Result<VPNStatus, ClientError>]
  let actionError: ClientError?
  let actionGate: Gate?
  let statusGate: Gate?
  let heldStatusCall: Int

  init(
    _ statuses: [Result<VPNStatus, ClientError>], actionError: ClientError? = nil,
    startupError: ClientError? = nil,
    actionGate: Gate? = nil, statusGate: Gate? = nil, heldStatusCall: Int = 0
  ) {
    self.statuses = statuses
    self.startupError = startupError
    self.actionError = actionError
    self.actionGate = actionGate
    self.statusGate = statusGate
    self.heldStatusCall = heldStatusCall
  }
  func startSession() async throws {
    sessionCalls += 1
    if let startupError { throw startupError }
  }
  func status() async throws -> VPNStatus {
    statusCalls += 1
    let response = statuses.count > 1 ? statuses.removeFirst() : statuses[0]
    if statusCalls == heldStatusCall { await statusGate?.wait() }
    return try response.get()
  }
  func perform(_ action: VPNAction) async throws {
    actions.append(action)
    await actionGate?.wait()
    if let actionError { throw actionError }
  }
}

@Test func discoveryUsesOnlyValidRegularTOMLFiles() throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: directory) }
  for name in ["work.toml", "home.toml", "bad name.toml", "notes.txt", ".hidden.toml"] {
    // Deliberately invalid contents: discovery must never parse profiles.
    try Data("not a profile".utf8).write(to: directory.appendingPathComponent(name))
  }
  try FileManager.default.createDirectory(
    at: directory.appendingPathComponent("folder.toml"), withIntermediateDirectories: true
  )
  try FileManager.default.createSymbolicLink(
    at: directory.appendingPathComponent("link.toml"),
    withDestinationURL: directory.appendingPathComponent("work.toml")
  )
  let files = try ProfileDiscovery.discover(in: directory)
  #expect(files.keys.sorted() == ["home", "work"])
  #expect(try ProfileDiscovery.discover(in: directory.appendingPathComponent("missing")).isEmpty)
}

@Test func profileNamesMatchCLIConstraints() {
  for name in ["work", "1", "a.b-c_d", String(repeating: "a", count: 64)] {
    #expect(ProfileDiscovery.validName(name))
  }
  for name in [
    "", ".hidden", "-flag", "../escape", "a/b", "ü", "two words", String(repeating: "a", count: 65),
  ] {
    #expect(!ProfileDiscovery.validName(name))
  }
}

@Test func statusDecodesCLIShapeAndKeepsMissingActiveProfiles() throws {
  let data = Data(
    """
    {"profiles":[
      {"name":"work","priority":100,"interface":"utun8","state":"connected","dns":"owner","routes":[]},
      {"name":"backup","priority":0,"interface":"utun9","state":"standby","dns":{"shadowed":{"by":"work"}},"routes":[]}
    ],"recovery_pending":false,"dns_owner":"work","shadowed_dns":["backup"]}
    """.utf8)
  let decoded = try JSONDecoder().decode(VPNStatus.self, from: data)
  let rows = ProfileDiscovery.rows(
    files: ["home": URL(fileURLWithPath: "/home.toml")], status: decoded)
  #expect(rows.map(\.name) == ["backup", "home", "work"])
  #expect(rows[0].title == "backup — Standby")
  #expect(rows[0].isActive && rows[2].isActive)
  #expect(rows[2].file == nil)
  #expect(!rows[1].isActive)
}

@Test func commandsReuseAppLifetimeAuthorizationAndPreserveArguments() async throws {
  let executable = URL(fileURLWithPath: "/Apps/John's $VPN/Helpers/simplevpn")
  let app = URL(fileURLWithPath: "/Apps/John's $VPN/MacOS/SimpleVPNMenuBar")
  let file = URL(fileURLWithPath: "/Users/John's folder/$(touch nope)/work.toml")
  let runner = RecordingRunner(CommandOutput(code: 0))
  let probe = SessionProbe()
  let client = CLIClient(
    executable: executable, authorizationExecutable: app, runner: runner,
    session: AppSession { try await probe.connect() })
  try await client.startSession()
  try await client.perform(.connect(file))
  try await client.perform(.disconnect("work"))
  try await client.perform(.disconnectAll)
  try await client.perform(.connect(file))
  let requests = await runner.requests
  #expect(requests.count == 5)
  #expect(await runner.timeouts == Array(repeating: .seconds(180), count: 5))
  #expect(requests.filter { $0.0 == app }.count == 1)
  #expect(requests[0].1 == [AuthorizationHelper.argument, "__authorize-app"])
  #expect(requests[1].0 == executable)
  #expect(requests[1].1 == ["--no-elevate", "up", "--", file.path])
  #expect(requests[2].1 == ["--no-elevate", "down", "--", "work"])
  #expect(requests[3].1 == ["--no-elevate", "down", "--all"])
  #expect(requests[4].1 == requests[1].1)
  #expect(await probe.attempts == 2)
}

@Test func existingSupervisorSessionNeedsNoAuthorization() async throws {
  let runner = RecordingRunner(CommandOutput(code: 0))
  let client = CLIClient(
    executable: URL(fileURLWithPath: "/simplevpn"),
    authorizationExecutable: URL(fileURLWithPath: "/app"), runner: runner, session: readySession())
  try await client.startSession()
  try await client.perform(.disconnectAll)
  let requests = await runner.requests
  #expect(requests.count == 1)
  #expect(requests[0].1 == ["--no-elevate", "down", "--all"])
}

@Test func commandFailuresNeverPromptOrReplayTheAction() async throws {
  for code: Int32 in [1, 2, 3, 4] {
    let runner = RecordingRunner(CommandOutput(code: code, stderr: Data("failed".utf8)))
    let executable = URL(fileURLWithPath: "/simplevpn")
    let client = CLIClient(
      executable: executable, authorizationExecutable: URL(fileURLWithPath: "/app"), runner: runner,
      session: readySession())
    await #expect(throws: ClientError.self) { try await client.perform(.disconnectAll) }
    let requests = await runner.requests
    #expect(requests.count == 1)
    #expect(requests[0].0 == executable)
  }
}

@Test func stoppedHelperRequestsFreshAuthorization() async throws {
  let runner = RecordingRunner(CommandOutput(code: 0))
  let app = URL(fileURLWithPath: "/app")
  let probe = SessionProbe()
  let client = CLIClient(
    executable: URL(fileURLWithPath: "/simplevpn"), authorizationExecutable: app, runner: runner,
    session: AppSession { try await probe.connect() })
  try await client.perform(.disconnectAll)
  try await client.perform(.disconnectAll)
  await probe.stopSupervisor()
  try await client.perform(.disconnectAll)
  #expect(await runner.requests.filter { $0.0 == app }.count == 2)
}

@Test func concurrentSessionRequestsShareOneAuthorization() async throws {
  let probe = SessionProbe()
  let gate = Gate()
  let session = AppSession { try await probe.connect() }
  let first = Task { try await session.ensure { await gate.wait() } }
  await gate.waitUntilArrived()
  let second = Task {
    try await session.ensure { Issue.record("Duplicate authorization request") }
  }
  await gate.open()
  try await first.value
  try await second.value
  #expect(await probe.attempts == 2)
}

@Test func sessionProtocolErrorsNeverTriggerAuthorization() async throws {
  let session = AppSession { throw ClientError.command("Invalid response") }
  await #expect(throws: ClientError.self) {
    try await session.ensure { Issue.record("Unexpected authorization") }
  }
}

@Test @MainActor func appleScriptQuotesMetacharactersWithoutElevation() async throws {
  // Round-trip the quoted command through the production Apple event without
  // requesting authorization, then execute the harmless command separately.
  let script = AuthorizationHelper.script.replacingOccurrences(
    of: "do shell script (item 1 of argv) with administrator privileges",
    with: "return item 1 of argv"
  )
  let values = [
    "space here", "a'b", "$(printf INJECTED)", "`printf INJECTED`", "a; printf INJECTED", "a\nb",
    "a\\b", "\"quote\"", "Büro 🔒", "--invoking-uid", "501", "",
  ]
  let command = AuthorizationHelper.shellCommand(["/usr/bin/printf", "%s|", "--"] + values)
  let quoted = AuthorizationHelper.execute(
    script: script, arguments: [command]
  )
  try #require(quoted.code == 0, "\(String(decoding: quoted.stderr, as: UTF8.self))")
  let output = try await ProcessRunner().run(
    executable: URL(fileURLWithPath: "/bin/sh"),
    arguments: ["-c", String(decoding: quoted.stdout, as: UTF8.self)]
  )
  #expect(output.code == 0)
  let actual = String(decoding: output.stdout, as: UTF8.self)
  #expect(actual == (["--"] + values).joined(separator: "|") + "|")
}

@Test @MainActor func authorizationHelperPreservesScriptCancellationAndErrors() {
  let command = "do shell script (item 1 of argv) with administrator privileges"
  let cancelled = AuthorizationHelper.execute(
    script: AuthorizationHelper.script.replacingOccurrences(
      of: command, with: "error \"User canceled.\" number -128"), arguments: [])
  #expect(cancelled.code == 0)
  #expect(String(decoding: cancelled.stdout, as: UTF8.self) == "SIMPLEVPN_AUTH_CANCELLED\n")
  let failed = AuthorizationHelper.execute(
    script: AuthorizationHelper.script.replacingOccurrences(
      of: command, with: "error \"invalid profile\" number 2"), arguments: [])
  #expect(failed.code != 0)
  #expect(String(decoding: failed.stderr, as: UTF8.self).contains("invalid profile"))
}

@Test @MainActor func authorizationHelperRejectsUnexpectedCommandsWithoutElevation() {
  for arguments in [
    [], ["status"], ["up"], ["up", "work.toml"], ["down", "--all", "extra"],
    ["--invoking-uid", "0", "down", "--all"], ["/bin/sh", "-c", "true"],
  ] {
    let result = AuthorizationHelper.run(
      executable: URL(fileURLWithPath: "/bundled/simplevpn"), uid: 501, arguments: arguments)
    #expect(result.code != 0)
    #expect(
      String(decoding: result.stderr, as: UTF8.self) == "Invalid VPN authorization request.\n")
  }
}

@Test func statusNeverElevatesAndRejectsInvalidJSON() async throws {
  let runner = RecordingRunner(CommandOutput(code: 0, stdout: Data("invalid".utf8)))
  let executable = URL(fileURLWithPath: "/bundled/simplevpn")
  let client = CLIClient(
    executable: executable, authorizationExecutable: URL(fileURLWithPath: "/app"), runner: runner,
    session: readySession())
  await #expect(throws: ClientError.self) { try await client.status() }
  let requests = await runner.requests
  #expect(requests[0].0 == executable)
  #expect(requests[0].1 == ["status", "--json"])
  #expect(await runner.timeouts == [.seconds(15)])
}

@Test func authorizationCancellationIsDistinctFromFailure() async throws {
  let probe = SessionProbe()
  let cancelled = CLIClient(
    executable: URL(fileURLWithPath: "/simplevpn"),
    authorizationExecutable: URL(fileURLWithPath: "/app"),
    runner: RecordingRunner(responses: [
      CommandOutput(code: 0, stdout: Data("SIMPLEVPN_AUTH_CANCELLED\n".utf8))
    ]), session: AppSession { try await probe.connect() }
  )
  do {
    try await cancelled.perform(.disconnectAll)
    Issue.record("Expected cancellation")
  } catch ClientError.cancelled {} catch { Issue.record("Unexpected error: \(error)") }
  let failed = CLIClient(
    executable: URL(fileURLWithPath: "/simplevpn"),
    authorizationExecutable: URL(fileURLWithPath: "/app"),
    runner: RecordingRunner(CommandOutput(code: 2, stderr: Data("invalid profile".utf8))),
    session: readySession())
  do {
    try await failed.perform(.disconnectAll)
    Issue.record("Expected failure")
  } catch { #expect(error.localizedDescription == "invalid profile") }
}

@Test func processRunnerCapturesLargeOutputsAndPreservesExitStatus() async throws {
  let output = try await ProcessRunner().run(
    executable: URL(fileURLWithPath: "/bin/sh"),
    arguments: ["-c", "head -c 131072 /dev/zero; head -c 131072 /dev/zero >&2; exit 7"]
  )
  #expect(output.code == 7)
  #expect(output.stdout.count == 131072)
  #expect(output.stderr.count == 131072)
}

@Test func processRunnerDoesNotWaitForInheritedOutputHandles() async throws {
  let clock = ContinuousClock()
  let started = clock.now
  let output = try await ProcessRunner().run(
    executable: URL(fileURLWithPath: "/bin/sh"),
    arguments: ["-c", "sleep 2 & printf done"]
  )
  #expect(clock.now - started < .seconds(1))
  #expect(output.code == 0)
  #expect(String(decoding: output.stdout, as: UTF8.self) == "done")
}

@Test func processRunnerTimesOutAndReapsItsChild() async throws {
  let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: path) }
  let clock = ContinuousClock()
  let started = clock.now
  do {
    _ = try await ProcessRunner().run(
      executable: URL(fileURLWithPath: "/bin/sh"),
      arguments: ["-c", "printf '%s' \"$$\" > \"$1\"; exec sleep 10", "probe", path.path],
      timeout: .milliseconds(200)
    )
    Issue.record("Expected timeout")
  } catch ClientError.timedOut {}
  #expect(clock.now - started < .seconds(2))
  let pid = try #require(Int32(String(contentsOf: path, encoding: .utf8)))
  #expect(waitpid(pid, nil, WNOHANG) == -1)
  #expect(errno == ECHILD)
}

@Test func processRunnerCancellationReapsItsChild() async throws {
  let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: path) }
  let operation = Task {
    try await ProcessRunner().run(
      executable: URL(fileURLWithPath: "/bin/sh"),
      arguments: ["-c", "printf '%s' \"$$\" > \"$1\"; exec sleep 10", "probe", path.path],
      timeout: .seconds(5)
    )
  }
  defer { operation.cancel() }
  let deadline = ContinuousClock.now.advanced(by: .seconds(2))
  while !FileManager.default.fileExists(atPath: path.path) && ContinuousClock.now < deadline {
    try await Task.sleep(for: .milliseconds(20))
  }
  let pid = try #require(Int32(String(contentsOf: path, encoding: .utf8)))
  let started = ContinuousClock.now
  operation.cancel()
  await #expect(throws: CancellationError.self) { try await operation.value }
  #expect(ContinuousClock.now - started < .seconds(1))
  #expect(waitpid(pid, nil, WNOHANG) == -1)
  #expect(errno == ECHILD)
}

@Test func processRunnerReportsLaunchFailureAndExcessiveOutput() async throws {
  await #expect(throws: POSIXError.self) {
    try await ProcessRunner().run(
      executable: URL(fileURLWithPath: "/missing-simplevpn-\(UUID().uuidString)"), arguments: [])
  }
  await #expect(throws: ClientError.self) {
    try await ProcessRunner().run(
      executable: URL(fileURLWithPath: "/usr/bin/head"), arguments: ["-c", "1048577", "/dev/zero"])
  }
}

@Test @MainActor func timedOutDisconnectReconcilesActualStateAndClearsUpdating() async {
  let client = StubClient(
    [
      .success(status([("work", .connected)])), .success(status()),
    ], actionError: .timedOut)
  let model = MenuController(
    client: client, discover: { ["work": URL(fileURLWithPath: "/work.toml")] })
  var errors: [String] = []
  model.onError = {
    #expect(!model.isBusy)
    errors.append($0)
  }
  await model.refresh()
  await model.disconnectAll()
  #expect(!model.isBusy && model.canToggle && !model.canDisconnectAll)
  #expect(model.summary == "No active profiles")
  #expect(model.rows.allSatisfy { !$0.isActive })
  #expect(await client.statusCalls == 2)
  #expect(errors == [ClientError.timedOut.localizedDescription])
}

@Test @MainActor func togglesIndependentlyAndDisconnectsProfilesMissingOnDisk() async {
  let client = StubClient([
    .success(status([("external", .connected)])),
    .success(status([("external", .connected), ("work", .connected)])),
    .success(status([("work", .connected)])),
  ])
  let file = URL(fileURLWithPath: "/work.toml")
  let model = MenuController(client: client, discover: { ["work": file] })
  await model.refresh()
  await model.toggle("work")
  #expect(model.rows.filter(\.isActive).count == 2)
  await model.toggle("external")
  #expect(await client.actions == [.connect(file), .disconnect("external")])
  #expect(model.rows.map(\.name) == ["work"])
}

@Test @MainActor func cancellationAndFailureRefreshActualState() async {
  for error in [ClientError.cancelled, ClientError.command("Connection failed")] {
    let client = StubClient([.success(status()), .success(status())], actionError: error)
    let model = MenuController(
      client: client, discover: { ["work": URL(fileURLWithPath: "/work.toml")] })
    var errors: [String] = []
    model.onError = { errors.append($0) }
    await model.refresh()
    await model.toggle("work")
    #expect(!model.isBusy)
    #expect(model.rows.allSatisfy { !$0.isActive })
    #expect(await client.statusCalls == 2)
    if case .cancelled = error {
      #expect(errors.isEmpty)
    } else {
      #expect(errors == ["Connection failed"])
    }
  }
}

@Test @MainActor func serializesActionsWhileAuthorizationIsPending() async {
  let gate = Gate()
  let client = StubClient([.success(status())], actionGate: gate)
  let model = MenuController(
    client: client, discover: { ["work": URL(fileURLWithPath: "/work.toml")] })
  await model.refresh()
  let operation = Task { await model.toggle("work") }
  await gate.waitUntilArrived()
  #expect(model.isBusy && !model.canToggle && !model.canDisconnectAll)
  await model.toggle("work")
  await model.disconnectAll()
  await model.refresh()
  #expect(await client.actions.count == 1)
  #expect(await client.statusCalls == 1)
  await gate.open()
  await operation.value
  #expect(!model.isBusy)
}

@Test @MainActor func oldRefreshCannotOverwriteActionResult() async {
  let gate = Gate()
  let client = StubClient(
    [.success(status()), .success(status()), .success(status([("work", .connected)]))],
    statusGate: gate, heldStatusCall: 2)
  let model = MenuController(
    client: client, discover: { ["work": URL(fileURLWithPath: "/work.toml")] })
  await model.refresh()
  let staleRefresh = Task { await model.refresh() }
  await gate.waitUntilArrived()
  await model.toggle("work")
  await gate.open()
  await staleRefresh.value
  #expect(model.rows.first?.isActive == true)
}

@Test @MainActor func recoveryAllowsDisconnectAllButNotProfileToggles() async {
  let client = StubClient([.success(status(recovery: true)), .success(status())])
  let model = MenuController(client: client, discover: { [:] })
  await model.refresh()
  #expect(!model.canToggle && model.canDisconnectAll)
  #expect(model.summary.contains("Recovery required"))
  await model.disconnectAll()
  #expect(await client.actions == [.disconnectAll])
  #expect(!model.canDisconnectAll)
}

@Test @MainActor func reconnectingProfilesRemainDisconnectable() async throws {
  let data = Data(
    #"{"profiles":[{"name":"work","state":"reconnecting"}],"recovery_pending":false}"#.utf8)
  let reconnecting = try JSONDecoder().decode(VPNStatus.self, from: data)
  for disconnectAll in [false, true] {
    let client = StubClient([.success(reconnecting), .success(status())])
    let model = MenuController(client: client, discover: { [:] })
    await model.refresh()
    #expect(model.summary == "Reconnecting VPN…")
    #expect(model.canToggle && model.canDisconnectAll)
    #expect(model.rows.first?.isActive == true)
    #expect(model.rows.first?.title == "work — Reconnecting")
    if disconnectAll {
      await model.disconnectAll()
      #expect(await client.actions == [.disconnectAll])
    } else {
      await model.toggle("work")
      #expect(await client.actions == [.disconnect("work")])
    }
    #expect(model.summary == "No active profiles")
  }
}

@Test @MainActor func statusFailureDisablesActionsAndRecoversOnRefresh() async {
  let client = StubClient([
    .success(status([("work", .connected)])),
    .failure(.command("unavailable")), .success(status()),
  ])
  let model = MenuController(client: client, discover: { [:] })
  await model.refresh()
  await model.refresh()
  #expect(model.statusError == "unavailable")
  #expect(!model.canToggle && !model.canDisconnectAll)
  await model.toggle("work")
  #expect(await client.actions.isEmpty)
  await model.refresh()
  #expect(model.statusError == nil && model.rows.isEmpty)
}

private final class StubConnection: SupervisorConnection, @unchecked Sendable {
  private let lock = NSLock()
  private var open = true
  var isOpen: Bool { lock.withLock { open } }
  func close() { lock.withLock { open = false } }
}

private func readySession() -> AppSession { AppSession { StubConnection() } }

private actor SessionProbe {
  var attempts = 0
  private var needsAuthorization = true
  private var connection = StubConnection()
  func connect() throws -> any SupervisorConnection {
    attempts += 1
    if needsAuthorization {
      needsAuthorization = false
      throw SessionError.authorizationRequired
    }
    return connection
  }
  func stopSupervisor() {
    connection.close()
    connection = StubConnection()
    needsAuthorization = true
  }
}

private func socketPair() throws -> (Int32, FileHandle) {
  var descriptors: [Int32] = [-1, -1]
  guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
    throw POSIXError(.EIO)
  }
  var deadline = timeval(tv_sec: 1, tv_usec: 0)
  for descriptor in descriptors {
    _ = setsockopt(
      descriptor, SOL_SOCKET, SO_RCVTIMEO, &deadline,
      socklen_t(MemoryLayout.size(ofValue: deadline)))
  }
  return (descriptors[0], FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: true))
}

private func sendSessionReply(_ text: String, on server: FileHandle) throws {
  let data = Data(text.utf8)
  var length = UInt32(data.count).bigEndian
  try server.write(contentsOf: withUnsafeBytes(of: &length) { Data($0) } + data)
}

@Test func sessionSocketUsesFramedProtocolAndDetectsSupervisorExit() throws {
  let (descriptor, server) = try socketPair()
  defer { try? server.close() }
  let connection = SessionSocket(descriptor: descriptor)
  try sendSessionReply(#"{"result":"ok","message":"App session opened"}"#, on: server)
  try connection.handshake(expectedUID: getuid())
  let header = try #require(try server.read(upToCount: 4))
  let count = header.reduce(0) { ($0 << 8) | Int($1) }
  let request = try #require(try server.read(upToCount: count))
  #expect(String(decoding: request, as: UTF8.self) == #"{"command":"app_session"}"#)
  #expect(connection.isOpen)
  try server.close()
  #expect(!connection.isOpen)
}

@Test func sessionSocketRejectsUntrustedServerBeforeSending() throws {
  if getuid() == 0 { return }
  let (descriptor, server) = try socketPair()
  defer { try? server.close() }
  let connection = SessionSocket(descriptor: descriptor)
  #expect(throws: ClientError.self) { try connection.handshake() }
  var byte: UInt8 = 0
  #expect(recv(server.fileDescriptor, &byte, 1, MSG_DONTWAIT) == -1)
  #expect(errno == EAGAIN || errno == EWOULDBLOCK)
}

@Test func sessionSocketDistinguishesAuthorizationFromProtocolFailure() throws {
  for (reply, needsAuthorization) in [
    (#"{"result":"error","exit_status":5,"message":"authorize"}"#, true),
    (#"{"result":"error","exit_status":1,"message":"failed"}"#, false),
    ("invalid JSON", false),
  ] {
    let (descriptor, server) = try socketPair()
    defer { try? server.close() }
    let connection = SessionSocket(descriptor: descriptor)
    try sendSessionReply(reply, on: server)
    do {
      try connection.handshake(expectedUID: getuid())
      Issue.record("Expected handshake failure")
    } catch SessionError.authorizationRequired {
      #expect(needsAuthorization)
    } catch {
      #expect(!needsAuthorization)
    }
  }
}

@Test func releasingAppSessionClosesItsSocket() async throws {
  let (descriptor, server) = try socketPair()
  defer { try? server.close() }
  var session: AppSession? = AppSession { SessionSocket(descriptor: descriptor) }
  try await session?.ensure { Issue.record("Unexpected authorization") }
  session = nil
  var byte: UInt8 = 0
  #expect(Darwin.read(server.fileDescriptor, &byte, 1) == 0)
}

@Test @MainActor func startupCancellationKeepsStatusAvailableWithoutRepeatedPrompts() async {
  let client = StubClient([.success(status())], startupError: .cancelled)
  let controller = MenuController(
    client: client, discover: { ["work": URL(fileURLWithPath: "/work.toml")] })
  controller.onError = { _ in Issue.record("Cancellation is not an error") }
  await controller.start()
  await controller.refresh()
  #expect(await client.sessionCalls == 1)
  #expect(!controller.isBusy)
  #expect(controller.canToggle)
  #expect(controller.statusError == nil)
}

@Test(
  .enabled(
    if: ProcessInfo.processInfo.environment["SIMPLEVPN_RUN_SOCKET_TESTS"] == "1",
    "Requires filesystem Unix socket binding outside restricted sandboxes"
  ))
func sessionSocketConnectsToLocalListenerWithCloseOnExec() async throws {
  let path = "/private/tmp/simplevpn-session-\(UUID().uuidString).sock"
  let listener = socket(AF_UNIX, SOCK_STREAM, 0)
  try #require(listener >= 0)
  defer {
    Darwin.close(listener)
    unlink(path)
  }
  var address = sockaddr_un()
  address.sun_family = sa_family_t(AF_UNIX)
  address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
  withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
  let bound = withUnsafePointer(to: &address) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
  }
  try #require(bound == 0, "Socket bind failed: \(String(cString: strerror(errno)))")
  try #require(listen(listener, 1) == 0)
  let server = Task.detached {
    let descriptor = accept(listener, nil, nil)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    try sendSessionReply(#"{"result":"ok","message":"ready"}"#, on: handle)
    return handle
  }
  let connection = try await Task.detached {
    try SessionSocket.open(path: path, expectedUID: getuid())
  }.value
  let handle = try await server.value
  defer { try? handle.close() }
  #expect(connection.isOpen)
  #expect(fcntl(connection.descriptor, F_GETFD) & FD_CLOEXEC != 0)
}
