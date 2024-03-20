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

extension Duration {
    /// The value of a positive duration in milliseconds, suitable to be encoded in WebAuthn types.
    var milliseconds: Int64 {
        let (seconds, attoseconds) = self.components
        return Int64(seconds * 1000) + Int64(attoseconds/1_000_000_000_000_000)
    }
}
