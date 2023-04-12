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
    static var mockChallenge: URLEncodedBase64 = "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg"
    static var mockCredentialID: URLEncodedBase64 = [0, 1, 2, 3, 4].base64URLEncodedString()
}
