//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2023 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift WebAuthn project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

package struct ChallengeGenerator: Sendable {
    var generate: @Sendable () -> [UInt8]

    package static var live: Self {
        .init(generate: { [UInt8].random(count: 32) })
    }
}
