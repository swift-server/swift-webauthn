//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2023 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

public struct ChallengeGenerator {
    var generate: () -> [UInt8]

    public static var live: Self {
        .init(generate: { [UInt8].random(count: 32) })
    }
}
