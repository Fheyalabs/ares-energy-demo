// swift-tools-version: 6.0
import PackageDescription
import Foundation

let openFHEEnabled = ProcessInfo.processInfo.environment["ARES_OPENFHE"] != nil

let openFHEIncludeFlags: [String] = [
    "-std=c++17",
    "-DOPENFHE_VERSION=v1.5.1",
    "-I/usr/local/include/openfhe",
    "-I/usr/local/include/openfhe/pke",
    "-I/usr/local/include/openfhe/core",
    "-I/usr/local/include/openfhe/cereal",
    "-I/usr/local/include/openfhe/binfhe",
    "-I/opt/homebrew/include/openfhe",
    "-I/opt/homebrew/include/openfhe/pke",
    "-I/opt/homebrew/include/openfhe/core",
    "-I/opt/homebrew/include/openfhe/cereal",
    "-I/opt/homebrew/include/openfhe/binfhe",
]

let openFHELinkFlags: [String] = [
    "-L/usr/local/lib",
    "-L/opt/homebrew/lib",
    "-lOPENFHEpke",
    "-lOPENFHEbinfhe",
    "-lOPENFHEcore",
    "-Xlinker", "-rpath", "-Xlinker", "/usr/local/lib",
    "-Xlinker", "-rpath", "-Xlinker", "/opt/homebrew/lib",
]

var allTargets: [Target] = [
    .target(
        name: "AresClient",
        dependencies: [.product(name: "Crypto", package: "swift-crypto")]
    ),
    .testTarget(
        name: "AresClientTests",
        dependencies: ["AresClient"]
    ),
    .target(
        name: "AresTransport",
        dependencies: ["AresClient", .product(name: "Crypto", package: "swift-crypto")]
    ),
    .testTarget(
        name: "AresTransportTests",
        dependencies: ["AresTransport"]
    ),
]

if openFHEEnabled {
    allTargets += [
        .target(
            name: "COpenFHEBridge",
            publicHeadersPath: "include",
            cxxSettings: [
                .unsafeFlags(openFHEIncludeFlags),
            ],
            linkerSettings: [
                .unsafeFlags(openFHELinkFlags),
            ]
        ),
        .target(
            name: "AresClientFHE",
            dependencies: ["COpenFHEBridge", .product(name: "Crypto", package: "swift-crypto")]
        ),
        .testTarget(
            name: "AresClientFHETests",
            dependencies: ["AresClientFHE", "COpenFHEBridge"]
        ),
        .executableTarget(
            name: "AresSmoke",
            dependencies: ["AresClient", "AresClientFHE", "AresTransport"]),
        .executableTarget(
            name: "FheyaMacClient",
            dependencies: ["AresClient", "AresClientFHE", "AresTransport", .product(name: "Crypto", package: "swift-crypto")],
            path: "Sources/MacClient"
        ),
    ]
}

// The FHE library product is only valid when its targets exist (ARES_OPENFHE
// set); declaring it unconditionally makes SwiftPM reject the manifest for
// referencing missing targets, which blocks no-OpenFHE builds of AresTransport.
var allProducts: [Product] = [
    .library(name: "AresClient", targets: ["AresClient"]),
    .library(name: "AresTransport", targets: ["AresTransport"]),
]
if openFHEEnabled {
    allProducts.append(.library(name: "AresClientFHE", targets: ["AresClientFHE", "COpenFHEBridge"]))
}

let package = Package(
    name: "AresClient",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: allProducts,
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: allTargets
)
