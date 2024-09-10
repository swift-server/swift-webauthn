//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2024 the WebAuthn Swift project authors
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

final class AuthenticatorAttestationGloballyUniqueIDTests: XCTestCase {
    func testByteCoding() throws {
        let aaguid = AuthenticatorAttestationGloballyUniqueID(bytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        XCTAssertNotNil(aaguid)
        XCTAssertEqual(aaguid?.bytes, [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
        XCTAssertEqual(aaguid?.id, UUID(uuid: (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f)))
        XCTAssertEqual(aaguid, AuthenticatorAttestationGloballyUniqueID(uuid: UUID(uuid: (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f))))
        XCTAssertEqual(aaguid, AuthenticatorAttestationGloballyUniqueID(uuidString: "00010203-0405-0607-0809-0A0B0C0D0E0F" ))
    }
    
    func testInvalidByteDecoding() throws {
        XCTAssertNil(AuthenticatorAttestationGloballyUniqueID(bytes: []))
        XCTAssertNil(AuthenticatorAttestationGloballyUniqueID(bytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]))
        XCTAssertNil(AuthenticatorAttestationGloballyUniqueID(bytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]))
    }
}
