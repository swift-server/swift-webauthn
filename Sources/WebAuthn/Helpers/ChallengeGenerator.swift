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

package struct ChallengeGenerator: Sendable {
    static let challengeSize: Int = 32
    
    var generate: @Sendable (_ : [UInt8]) -> [UInt8]

    package static var live: Self {
        .init(generate: { challengeData in
            var randomData = [UInt8].random(count: challengeSize)
            randomData.append(contentsOf: challengeData)
            return randomData
        })
    }
}
