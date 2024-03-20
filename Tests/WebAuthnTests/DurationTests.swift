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

import XCTest
@testable import WebAuthn

final class DurationTests: XCTestCase {
    func testMilliseconds() throws {
        XCTAssertEqual(Duration.milliseconds(1234).milliseconds, 1234)
        XCTAssertEqual(Duration.milliseconds(-1234).milliseconds, -1234)
        XCTAssertEqual(Duration.microseconds(12345).milliseconds, 12)
        XCTAssertEqual(Duration.microseconds(-12345).milliseconds, -12)
    }
}
