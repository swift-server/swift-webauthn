// swift-tools-version:5.6
import PackageDescription

let package = Package(
    name: "PasskeyDemo",
    platforms: [
       .macOS(.v12)
    ],
    dependencies: [
        // 💧 A server-side Swift web framework.
        .package(url: "https://github.com/unrelentingtech/SwiftCBOR.git", from: "0.4.5"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "WebAuthn",
            dependencies: [
                "SwiftCBOR",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .testTarget(name: "WebAuthnTests", dependencies: [
            .target(name: "WebAuthn"),
        ])
    ]
)
