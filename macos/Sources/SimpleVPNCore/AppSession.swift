// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

protocol SupervisorConnection: Sendable {
  var isOpen: Bool { get }
}

enum SessionError: Error {
  case authorizationRequired
}

// The app owns this socket for its lifetime. The kernel closes it on normal
// termination and crashes, so the supervisor never relies on a quit command.
public actor AppSession {
  private let connect: @Sendable () async throws -> any SupervisorConnection
  private var connection: (any SupervisorConnection)?
  private var pending: Task<any SupervisorConnection, Error>?

  public init() {
    connect = {
      try await withCheckedThrowingContinuation { continuation in
        DispatchQueue.global(qos: .userInitiated).async {
          continuation.resume(with: Result { try SessionSocket.open() })
        }
      }
    }
  }

  init(connect: @escaping @Sendable () async throws -> any SupervisorConnection) {
    self.connect = connect
  }

  func ensure(authorize: @escaping @Sendable () async throws -> Void) async throws {
    if let pending {
      _ = try await pending.value
      return
    }
    if connection?.isOpen == true { return }
    connection = nil
    let operation = Task { [connect] in
      do { return try await connect() } catch SessionError.authorizationRequired {
        try Task.checkCancellation()
        try await authorize()
        return try await connect()
      }
    }
    pending = operation
    do {
      connection = try await operation.value
      pending = nil
    } catch {
      pending = nil
      throw error
    }
  }
}

// All blocking handshake I/O runs on a dispatch queue. After the handshake this
// immutable descriptor is only probed with nonblocking recv, and closed at deinit.
final class SessionSocket: SupervisorConnection, @unchecked Sendable {
  let descriptor: Int32

  init(descriptor: Int32) { self.descriptor = descriptor }
  deinit { Darwin.close(descriptor) }

  var isOpen: Bool {
    var byte: UInt8 = 0
    let result = recv(descriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
    return result < 0 && [EAGAIN, EWOULDBLOCK, EINTR].contains(errno)
  }

  static func open(path: String = "/var/run/simplevpn/control.sock", expectedUID: UInt32 = 0)
    throws -> SessionSocket
  {
    let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw failure("create session socket") }
    let connection = SessionSocket(descriptor: descriptor)
    guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
      throw failure("protect session socket")
    }
    var noSignal: Int32 = 1
    var sendTimeout = timeval(tv_sec: 5, tv_usec: 0)
    var receiveTimeout = timeval(tv_sec: 120, tv_usec: 0)
    guard
      setsockopt(
        descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
        socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0,
      setsockopt(
        descriptor, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout,
        socklen_t(MemoryLayout.size(ofValue: sendTimeout))) == 0,
      setsockopt(
        descriptor, SOL_SOCKET, SO_RCVTIMEO, &receiveTimeout,
        socklen_t(MemoryLayout.size(ofValue: receiveTimeout))) == 0
    else { throw failure("configure session socket") }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let pathBytes = Array(path.utf8) + [0]
    guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
      throw ClientError.command("Supervisor socket path is too long.")
    }
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }
    let result = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
      }
    }
    guard result == 0 else {
      if errno == ENOENT || errno == ECONNREFUSED { throw SessionError.authorizationRequired }
      throw failure("contact supervisor")
    }
    try connection.handshake(expectedUID: expectedUID)
    return connection
  }

  func handshake(expectedUID: UInt32 = 0) throws {
    var uid: uid_t = 0
    var gid: gid_t = 0
    guard getpeereid(descriptor, &uid, &gid) == 0, uid == expectedUID else {
      throw ClientError.command("Cannot authenticate the root VPN supervisor.")
    }
    let payload = Data(#"{"command":"app_session"}"#.utf8)
    var length = UInt32(payload.count).bigEndian
    var frame = withUnsafeBytes(of: &length) { Data($0) }
    frame.append(payload)
    try frame.withUnsafeBytes { bytes in
      var offset = 0
      while offset < bytes.count {
        let written = Darwin.write(
          descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
        if written < 0 && errno == EINTR { continue }
        guard written > 0 else { throw Self.failure("send app session request") }
        offset += written
      }
    }
    let header = try readExactly(4)
    let size = header.reduce(0) { ($0 << 8) | Int($1) }
    guard size > 0 && size <= 2 * 1024 * 1024 else {
      throw ClientError.command("Invalid supervisor session response size.")
    }
    struct Reply: Decodable {
      let result: String
      let exitStatus: UInt8?
      let message: String

      enum CodingKeys: String, CodingKey {
        case result, message
        case exitStatus = "exit_status"
      }
    }
    let data = try readExactly(size)
    guard let reply = try? JSONDecoder().decode(Reply.self, from: data) else {
      throw ClientError.command("Invalid supervisor session response.")
    }
    if reply.result == "error" && reply.exitStatus == 5 {
      throw SessionError.authorizationRequired
    }
    guard reply.result == "ok" else { throw ClientError.command(reply.message) }
  }

  private func readExactly(_ count: Int) throws -> Data {
    var data = Data(count: count)
    try data.withUnsafeMutableBytes { bytes in
      var offset = 0
      while offset < count {
        let received = Darwin.read(
          descriptor, bytes.baseAddress!.advanced(by: offset), count - offset)
        if received < 0 && errno == EINTR { continue }
        guard received > 0 else {
          throw ClientError.command("Supervisor closed or timed out during app session setup.")
        }
        offset += received
      }
    }
    return data
  }

  private static func failure(_ action: String) -> ClientError {
    .command("Cannot \(action): \(String(cString: strerror(errno))).")
  }
}
