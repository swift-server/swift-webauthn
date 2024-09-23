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
import WebAuthn

struct TestClientDataJSON: Encodable {
    var type = "webauthn.create"
    var challenge: URLEncodedBase64 = TestConstants.mockChallenge.base64URLEncodedString()
    var origin = "https://example.com"
    var crossOrigin = false
    var randomOtherKey = "123"

    var base64URLEncoded: URLEncodedBase64 {
        jsonData.base64URLEncodedString()
    }

    /// Returns this `TestClientDataJSON` as encoded json. On **Linux** this is NOT idempotent. Subsequent calls
    /// will result in different `Data`
    var jsonData: Data {
        // swiftlint:disable:next force_try
        try! JSONEncoder().encode(self)
    }

    /// Returns this `TestClientDataJSON` as encoded json. On **Linux** this is NOT idempotent. Subsequent calls
    /// will result in different bytes
    var jsonBytes: [UInt8] {
        [UInt8](jsonData)
    }
}
