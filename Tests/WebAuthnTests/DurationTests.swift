//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Testing
@testable import WebAuthn

struct DurationTests {
    @Test
    func milliseconds() {
        #expect(Duration.milliseconds(1234).milliseconds == 1234)
        #expect(Duration.milliseconds(-1234).milliseconds == -1234)
        #expect(Duration.microseconds(12345).milliseconds == 12)
        #expect(Duration.microseconds(-12345).milliseconds == -12)
    }
}
