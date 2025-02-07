// swift-tools-version: 6.0
//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "swift-webauthn",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "WebAuthn", targets: ["WebAuthn"])
    ],
    dependencies: [
        .package(url: "https://github.com/unrelentingtech/SwiftCBOR.git", from: "0.4.7"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.8.1" ..< "4.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.1.0")
    ],
    targets: [
        .target(
            name: "WebAuthn",
            dependencies: [
                "SwiftCBOR",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .testTarget(
            name: "WebAuthnTests",
            dependencies: [
                .target(name: "WebAuthn"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        )
    ]
)
