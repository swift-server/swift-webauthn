// swift-tools-version:5.6
//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2022 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "webauthn-swift",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(name: "WebAuthn", targets: ["WebAuthn"])
    ],
    dependencies: [
        .package(url: "https://github.com/unrelentingtech/SwiftCBOR.git", from: "0.4.5"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "WebAuthn",
            dependencies: [
                "SwiftCBOR",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log")
            ]
        ),
        .testTarget(name: "WebAuthnTests", dependencies: [
            .target(name: "WebAuthn")
        ])
    ]
)
