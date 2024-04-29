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

import WebAuthn

struct TestConstants {
    /// Byte representation of string "randomStringFromServer"
    static let mockChallenge: [UInt8] = "72616e646f6d537472696e6746726f6d536572766572".hexadecimal!
    static let mockCredentialID: [UInt8] = [0, 1, 2, 3, 4]
}
