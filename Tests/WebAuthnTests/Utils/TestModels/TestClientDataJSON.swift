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
import WebAuthn

struct TestClientDataJSON: Encodable {
    var type = "webauthn.create"
    var challenge = TestConstants.mockChallenge
    var origin = "https://example.com"
    var crossOrigin = false
    var randomOtherKey = "123"

    var base64URLEncoded: URLEncodedBase64 {
        jsonData.base64URLEncodedString()
    }

    var jsonData: Data {
        // swiftlint:disable:next force_try
        try! JSONEncoder().encode(self)
    }
}
