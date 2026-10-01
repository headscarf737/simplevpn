// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

public struct VPNStatus: Decodable, Sendable, Equatable {
  public let profiles: [ActiveProfile]
  public let recoveryPending: Bool
  public let networkStatus: NetworkStatus?

  public init(profiles: [ActiveProfile], recoveryPending: Bool, networkStatus: NetworkStatus? = nil)
  {
    self.profiles = profiles
    self.recoveryPending = recoveryPending
    self.networkStatus = networkStatus
  }

  public var requiresRecovery: Bool {
    recoveryPending || networkStatus?.state == .blocked || networkStatus?.state == .recoveryRequired
  }

  public var profileChangesAllowed: Bool {
    !requiresRecovery && networkStatus?.state != .applying && networkStatus?.state != .disconnecting
  }

  enum CodingKeys: String, CodingKey {
    case profiles
    case recoveryPending = "recovery_pending"
    case networkStatus = "network_status"
  }
}

public struct NetworkStatus: Decodable, Sendable, Equatable {
  public let state: State
  public let protection: Protection
  public let reason: String?

  public enum State: String, Decodable, Sendable {
    case idle, applying, ready, recovering, blocked, disconnecting
    case recoveryRequired = "recovery_required"
  }
  public enum Protection: String, Decodable, Sendable {
    case verified, unverified
    case notRequired = "not_required"
  }
}

public struct ActiveProfile: Decodable, Sendable, Equatable {
  public let name: String
  public let state: State

  public enum State: String, Decodable, Sendable {
    case connected, reconnecting, standby
    case recoveryPending = "recovery_pending"
  }
}

public struct ProfileRow: Sendable, Equatable {
  public let name: String
  public let file: URL?
  public let state: ActiveProfile.State?

  public var isActive: Bool {
    state == .connected || state == .reconnecting || state == .standby
  }
  public var title: String {
    switch state {
    case .standby: "\(name) — Standby"
    case .reconnecting: "\(name) — Reconnecting"
    case .recoveryPending: "\(name) — Recovery pending"
    default: name
    }
  }
}

public enum ProfileDiscovery {
  public static var directory: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".config/simplevpn", isDirectory: true)
  }

  // Match the CLI's filename rules without opening profiles or reading keys.
  public static func validName(_ name: String) -> Bool {
    let bytes = Array(name.utf8)
    func alphanumeric(_ byte: UInt8) -> Bool {
      (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
    }
    return (1...64).contains(bytes.count) && bytes.first.map(alphanumeric) == true
      && bytes.allSatisfy { alphanumeric($0) || [45, 46, 95].contains($0) }
  }

  public static func discover(in directory: URL) throws -> [String: URL] {
    let files: [URL]
    do {
      files = try FileManager.default.contentsOfDirectory(
        at: directory, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
        options: [.skipsHiddenFiles]
      )
    } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
      return [:]
    }
    var profiles: [String: URL] = [:]
    for file in files where file.pathExtension == "toml" {
      let name = file.deletingPathExtension().lastPathComponent
      guard validName(name) else { continue }
      let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
      if values.isRegularFile == true && values.isSymbolicLink != true {
        profiles[name] = file
      }
    }
    return profiles
  }

  public static func rows(files: [String: URL], status: VPNStatus?) -> [ProfileRow] {
    var active: [String: ActiveProfile.State] = [:]
    for profile in status?.profiles ?? [] {
      if status?.requiresRecovery == true {
        active[profile.name] = .recoveryPending
      } else if let network = status?.networkStatus,
        network.state != .ready || network.protection == .unverified
      {
        active[profile.name] = .reconnecting
      } else {
        active[profile.name] = profile.state
      }
    }
    return Set(files.keys).union(active.keys).sorted().map {
      ProfileRow(name: $0, file: files[$0], state: active[$0])
    }
  }
}
