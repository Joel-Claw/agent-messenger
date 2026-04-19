// Agent Messenger - iOS Client
// Package.swift for Swift Package Manager dependencies

import PackageDescription

let package = Package(
    name: "AgentMessenger",
    platforms: [
        .iOS(.v16),
    ],
    products: [
        .library(name: "AgentMessengerKit", targets: ["AgentMessengerKit"]),
    ],
    dependencies: [
        // No external dependencies - using URLSessionWebSocketTask and native SwiftUI
    ],
    targets: [
        .target(
            name: "AgentMessengerKit",
            path: "Sources/AgentMessengerKit"
        ),
        .testTarget(
            name: "AgentMessengerKitTests",
            dependencies: ["AgentMessengerKit"],
            path: "Tests/AgentMessengerKitTests"
        ),
    ]
)