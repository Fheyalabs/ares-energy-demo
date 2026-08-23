// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AresClient",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "AresClient", targets: ["AresClient"]),
        .library(name: "AresTransport", targets: ["AresTransport"]),
        .library(name: "AresClientFHE", targets: ["AresClientFHE"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .binaryTarget(name: "COpenFHEBridge", path: "Artifacts/AresPrivacyCore.xcframework"),
        .target(
            name: "AresClient",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        ),
        .target(
            name: "AresTransport",
            dependencies: ["AresClient", .product(name: "Crypto", package: "swift-crypto")]
        ),
        .target(
            name: "AresClientFHE",
            dependencies: ["COpenFHEBridge", .product(name: "Crypto", package: "swift-crypto")],
            linkerSettings: [.linkedLibrary("c++")]
        ),
    ]
)
