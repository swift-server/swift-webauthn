//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2023 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

public struct ChallengeGenerator: Sendable {
    var generate: @Sendable () -> [UInt8]

    public static var live: Self {
        .init(generate: {
            // try to use secured random generator
            var bytes = [UInt8](repeating: 0, count: 32)
            let result = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            guard result == errSecSuccess else {
                return [UInt8].random(count: 32)
            }
            return bytes
        })
    }
}
