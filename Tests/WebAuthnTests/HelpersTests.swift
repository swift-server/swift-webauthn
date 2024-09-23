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

import XCTest

@testable import WebAuthn

final class HelpersTests: XCTestCase {
    func testBase64URLEncodeReturnsCorrectString() {
        let input: [UInt8] = [1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0]
        let expectedBase64 = "AQABAAEBAAEAAQEAAAABAA=="
        let expectedBase64URL = "AQABAAEBAAEAAQEAAAABAA"

        let base64Encoded = input.base64EncodedString()
        let base64URLEncoded = input.base64URLEncodedString()

        XCTAssertEqual(expectedBase64, base64Encoded.asString())
        XCTAssertEqual(expectedBase64URL, base64URLEncoded.asString())
    }

    func testEncodeBase64Codable() throws {
        let base64 = EncodedBase64("AQABAAEBAAEAAQEAAAABAA==")
        let json = try JSONEncoder().encode(base64)
        let decodedBase64 = try JSONDecoder().decode(EncodedBase64.self, from: json)
        XCTAssertEqual(base64, decodedBase64)
    }
}
