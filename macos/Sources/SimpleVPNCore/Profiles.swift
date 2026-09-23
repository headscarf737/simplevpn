// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

public struct VPNStatus: Decodable, Sendable, Equatable {
  public let profiles: [ActiveProfile]
  public let recoveryPending: Bool

  enum CodingKeys: String, CodingKey {
    case profiles
    case recoveryPending = "recovery_pending"
  }
}

public struct ActiveProfile: Decodable, Sendable, Equatable {
  public let name: String
  public let state: State

  public enum State: String, Decodable, Sendable {
    case connected, standby
    case recoveryPending = "recovery_pending"
  }
}

public struct ProfileRow: Sendable, Equatable {
  public let name: String
  public let file: URL?
  public let state: ActiveProfile.State?

  public var isActive: Bool { state == .connected || state == .standby }
  public var title: String {
    switch state {
    case .standby: "\(name) — Standby"
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
    for profile in status?.profiles ?? [] { active[profile.name] = profile.state }
    return Set(files.keys).union(active.keys).sorted().map {
      ProfileRow(name: $0, file: files[$0], state: active[$0])
    }
  }
}
