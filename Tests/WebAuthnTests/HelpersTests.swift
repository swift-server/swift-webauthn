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

import XCTest

@testable import WebAuthn

final class HelpersTests: XCTestCase {
    func testBase64URLEncodeReturnsCorrectString() {
        let input: [UInt8] = [1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0]
        let expectedBase64 = "AQABAAEBAAEAAQEAAAABAA=="
        let expectedBase64URL = "AQABAAEBAAEAAQEAAAABAA"
        let base64Encoded = EncodedBase64(bytes: input)
        let base64URLEncoded = URLEncodedBase64(bytes: input)
        
        XCTAssertEqual(expectedBase64, base64Encoded.value)
        XCTAssertEqual(expectedBase64URL, base64URLEncoded.value)
    }

    func testEncodeBase64Codable() throws {
        let base64 = EncodedBase64(base64Encoded: "AQABAAEBAAEAAQEAAAABAA==")
        let json = try JSONEncoder().encode(base64)
        let decodedBase64 = try JSONDecoder().decode(EncodedBase64.self, from: json)
        XCTAssertEqual(base64, decodedBase64)
    }
}
