//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2024 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import Testing
@testable import WebAuthn

struct AuthenticatorAttestationGloballyUniqueIDTests {
    @Test
    func byteCoding() {
        let aaguid = AuthenticatorAttestationGloballyUniqueID(bytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        #expect(aaguid != nil)
        #expect(aaguid?.bytes == [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
        #expect(aaguid?.id == UUID(uuid: (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f)))
        #expect(aaguid == AuthenticatorAttestationGloballyUniqueID(uuid: UUID(uuid: (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f))))
        #expect(aaguid == AuthenticatorAttestationGloballyUniqueID(uuidString: "00010203-0405-0607-0809-0A0B0C0D0E0F" ))
    }
    
    @Test
    func invalidByteDecoding() {
        #expect(AuthenticatorAttestationGloballyUniqueID(bytes: []) == nil)
        #expect(AuthenticatorAttestationGloballyUniqueID(bytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]) == nil)
        #expect(AuthenticatorAttestationGloballyUniqueID(bytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]) == nil)
    }
}
