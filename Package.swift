// swift-tools-version: 6.0
// SPDX-License-Identifier: Apache-2.0

import PackageDescription

let package = Package(
    name: "AresClient",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "AresClient", targets: ["AresClient"]),
        .library(name: "AresTransport", targets: ["AresTransport"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "AresClient",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")],
            path: "clients/swift/Sources/AresClient"
        ),
        .target(
            name: "AresTransport",
            dependencies: ["AresClient", .product(name: "Crypto", package: "swift-crypto")],
            path: "clients/swift/Sources/AresTransport"
        ),
        .testTarget(
            name: "AresClientTests",
            dependencies: ["AresClient"],
            path: "clients/swift/Tests/AresClientTests"
        ),
        .testTarget(
            name: "AresTransportTests",
            dependencies: ["AresTransport"],
            path: "clients/swift/Tests/AresTransportTests"
        ),
    ]
)
