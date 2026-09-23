// swift-tools-version: 6.0
// SPDX-License-Identifier: GPL-3.0-or-later
import PackageDescription

let package = Package(
  name: "SimpleVPNMenuBar",
  platforms: [.macOS(.v13)],
  products: [.executable(name: "SimpleVPNMenuBar", targets: ["SimpleVPNMenuBar"])],
  targets: [
    .target(name: "SimpleVPNCore"),
    .executableTarget(name: "SimpleVPNMenuBar", dependencies: ["SimpleVPNCore"]),
    .testTarget(name: "SimpleVPNCoreTests", dependencies: ["SimpleVPNCore"]),
  ]
)
