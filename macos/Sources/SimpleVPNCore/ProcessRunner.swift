// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

public struct ProcessRunner: CommandRunning {
  public init() {}

  public func run(executable: URL, arguments: [String], timeout: Duration = .seconds(180))
    async throws -> CommandOutput
  {
    let cancellation = CommandCancellation()
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        DispatchQueue.global(qos: .utility).async {
          continuation.resume(
            with: Result {
              try Self.capture(executable, arguments, timeout, cancellation)
            })
        }
      }
    } onCancel: {
      cancellation.cancel()
    }
  }

  // Neither child exit nor output capture depends on AppKit's run-loop mode.
  // Anonymous files also avoid waiting for EOF from a descendant that inherited stdout.
  private static func capture(
    _ executable: URL, _ arguments: [String], _ timeout: Duration,
    _ cancellation: CommandCancellation
  ) throws -> CommandOutput {
    if cancellation.isCancelled { throw CancellationError() }
    let output = try anonymousFile()
    defer { try? output.close() }
    let errors = try anonymousFile()
    defer { try? errors.close() }
    var actions: posix_spawn_file_actions_t?
    try check(posix_spawn_file_actions_init(&actions))
    defer { posix_spawn_file_actions_destroy(&actions) }
    try check(posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0))
    try check(posix_spawn_file_actions_adddup2(&actions, output.fileDescriptor, STDOUT_FILENO))
    try check(posix_spawn_file_actions_adddup2(&actions, errors.fileDescriptor, STDERR_FILENO))
    var attributes: posix_spawnattr_t?
    try check(posix_spawnattr_init(&attributes))
    defer { posix_spawnattr_destroy(&attributes) }
    try check(posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)))

    var argv: [UnsafeMutablePointer<CChar>?] = []
    defer { for entry in argv { free(entry) } }
    for value in [executable.path] + arguments {
      guard let value = strdup(value) else { throw POSIXError(.ENOMEM) }
      argv.append(value)
    }
    argv.append(nil)
    var environment: [UnsafeMutablePointer<CChar>?] = []
    defer { for entry in environment { free(entry) } }
    for (key, value) in ProcessInfo.processInfo.environment {
      guard let entry = strdup("\(key)=\(value)") else { throw POSIXError(.ENOMEM) }
      environment.append(entry)
    }
    environment.append(nil)
    var pid: pid_t = 0
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: timeout)
    try check(
      executable.path.withCString { program in
        argv.withUnsafeMutableBufferPointer { argv in
          environment.withUnsafeMutableBufferPointer { environment in
            posix_spawn(
              &pid, program, &actions, &attributes, argv.baseAddress!, environment.baseAddress!)
          }
        }
      })
    var reaped = false
    defer {
      if !reaped {
        // Kill only our CLI/authorization wrapper, never the privileged supervisor.
        // Reconcile separately because an already-dispatched VPN operation can finish.
        kill(pid, SIGKILL)
        while waitpid(pid, nil, 0) == -1 && errno == EINTR {}
      }
    }
    var status: Int32 = 0
    while true {
      let result = waitpid(pid, &status, WNOHANG)
      if result == pid {
        reaped = true
        break
      }
      if result == -1 {
        if errno == EINTR { continue }
        // Never signal a PID that is no longer our child.
        reaped = errno == ECHILD
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
      }
      if cancellation.isCancelled { throw CancellationError() }
      if clock.now >= deadline { throw ClientError.timedOut }
      Thread.sleep(forTimeInterval: 0.02)
    }
    if cancellation.isCancelled { throw CancellationError() }
    let signal = status & 0x7f
    let code = signal == 0 ? (status >> 8) & 0xff : 128 + signal
    return try CommandOutput(code: code, stdout: read(output), stderr: read(errors))
  }

  private static func check(_ code: Int32) throws {
    if code != 0 { throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO) }
  }

  private static func anonymousFile() throws -> FileHandle {
    var path = Array(
      FileManager.default.temporaryDirectory.appendingPathComponent("simplevpn-command-XXXXXX")
        .path.utf8CString)
    let descriptor = path.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    do {
      let unlinked = path.withUnsafeBufferPointer { unlink($0.baseAddress!) }
      guard unlinked == 0, fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
      }
      return handle
    } catch {
      try? handle.close()
      throw error
    }
  }

  private static func read(_ handle: FileHandle) throws -> Data {
    let maximum = 1024 * 1024
    try handle.seek(toOffset: 0)
    let data = try handle.read(upToCount: maximum + 1) ?? Data()
    guard data.count <= maximum else { throw ClientError.command("Command output exceeds 1 MiB.") }
    return data
  }
}

// Accessed by the worker and Swift's synchronous task-cancellation callback.
private final class CommandCancellation: @unchecked Sendable {
  private let lock = NSLock()
  private var cancelled = false
  var isCancelled: Bool { lock.withLock { cancelled } }
  func cancel() { lock.withLock { cancelled = true } }
}
