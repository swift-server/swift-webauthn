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

public protocol ChallengeGenerator : Sendable {
    func generate() -> [UInt8]
}

public struct DefaultChallengeGenerator: Sendable, ChallengeGenerator {
    public func generate() -> [UInt8] {
        return [UInt8].random(count: 32)
    }
    
    public static let live = DefaultChallengeGenerator()
}
