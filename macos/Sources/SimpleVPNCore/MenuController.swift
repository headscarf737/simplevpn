// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

@MainActor
public final class MenuController {
  public private(set) var status: VPNStatus?
  public private(set) var files: [String: URL] = [:]
  public private(set) var statusError: String?
  public private(set) var discoveryError: String?
  public private(set) var isBusy = false
  public var onChange: (() -> Void)?
  public var onError: ((String) -> Void)?

  private let client: any VPNClient
  private let discover: @Sendable () throws -> [String: URL]
  private var isRefreshing = false
  private var revision = 0

  public init(
    client: any VPNClient,
    discover: @escaping @Sendable () throws -> [String: URL] = {
      try ProfileDiscovery.discover(in: ProfileDiscovery.directory)
    }
  ) {
    self.client = client
    self.discover = discover
  }

  public var rows: [ProfileRow] { ProfileDiscovery.rows(files: files, status: status) }
  public var canToggle: Bool {
    !isBusy && status != nil && statusError == nil && status?.profileChangesAllowed == true
  }
  public var canDisconnectAll: Bool {
    !isBusy && statusError == nil
      && (status?.profiles.isEmpty == false || status?.requiresRecovery == true)
  }
  public var summary: String {
    if isBusy { return "Updating VPN…" }
    if statusError != nil { return "VPN status unavailable" }
    guard let status else { return "Loading VPN status…" }
    if status.networkStatus?.state == .blocked {
      return "Protection could not be verified — retrying…"
    }
    if status.requiresRecovery { return "Recovery required — use Disconnect All" }
    if status.networkStatus?.state == .recovering { return "Reconnecting VPN…" }
    if status.networkStatus?.state == .applying || status.networkStatus?.state == .disconnecting {
      return "Updating VPN…"
    }
    if status.profiles.contains(where: { $0.state == .reconnecting }) {
      return "Reconnecting VPN…"
    }
    switch status.profiles.count {
    case 0: return "No active profiles"
    case 1: return "1 active profile"
    case let count: return "\(count) active profiles"
    }
  }

  public func refresh() async {
    guard !isBusy && !isRefreshing else { return }
    isRefreshing = true
    let currentRevision = revision
    let discovery = await Task.detached { [discover] in Result { try discover() } }.value
    let result: Result<VPNStatus, Error>
    do { result = .success(try await client.status()) } catch { result = .failure(error) }
    isRefreshing = false
    // A status request begun before a click must not overwrite the action's result.
    guard revision == currentRevision else { return }
    applyDiscovery(discovery)
    apply(result)
    onChange?()
  }

  public func start() async {
    guard !isBusy else { return }
    isBusy = true
    revision += 1
    onChange?()
    var startupError: String?
    do {
      try await client.startSession()
    } catch ClientError.cancelled {
      // A later explicit VPN action can ask again; polling never prompts.
    } catch {
      startupError = error.localizedDescription
    }
    isBusy = false
    await refresh()
    if let startupError { onError?(startupError) }
  }

  public func toggle(_ name: String) async {
    guard canToggle, let row = rows.first(where: { $0.name == name }) else { return }
    if row.isActive {
      await perform(.disconnect(name))
    } else if let file = row.file {
      await perform(.connect(file))
    }
  }

  public func disconnectAll() async {
    guard canDisconnectAll else { return }
    await perform(.disconnectAll)
  }

  private func perform(_ action: VPNAction) async {
    isBusy = true
    revision += 1
    onChange?()
    var operationError: String?
    do {
      try await client.perform(action)
    } catch ClientError.cancelled {
      // Cancellation is not an operation failure.
    } catch {
      operationError = error.localizedDescription
    }
    // Always reconcile with the supervisor, even after cancellation or a CLI timeout.
    let discovery = await Task.detached { [discover] in Result { try discover() } }.value
    applyDiscovery(discovery)
    do { apply(.success(try await client.status())) } catch { apply(.failure(error)) }
    isBusy = false
    onChange?()
    if let operationError { onError?(operationError) }
  }

  private func apply(_ result: Result<VPNStatus, Error>) {
    switch result {
    case .success(let status):
      self.status = status
      statusError = nil
    case .failure(let error):
      status = nil
      statusError = error.localizedDescription
    }
  }

  private func applyDiscovery(_ result: Result<[String: URL], Error>) {
    switch result {
    case .success(let files):
      self.files = files
      discoveryError = nil
    case .failure(let error): discoveryError = error.localizedDescription
    }
  }
}
