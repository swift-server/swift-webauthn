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

@testable import WebAuthn

public struct MockChallengeGenerator : ChallengeGenerator {
    
    let challenge : [UInt8]
    public func generate() -> [UInt8] {
        return challenge
    }
    
}
extension ChallengeGenerator {
    static func mock(generate: [UInt8]) -> ChallengeGenerator {
        MockChallengeGenerator(challenge: generate)
    }
}
