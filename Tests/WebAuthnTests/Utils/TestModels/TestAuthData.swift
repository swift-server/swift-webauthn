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
import Crypto
import WebAuthn

struct TestAuthData {
    var relyingPartyIDHash: [UInt8]?
    var flags: UInt8?
    var counter: [UInt8]?
    var attestedCredData: [UInt8]?
    var extensions: [UInt8]?

    var byteArrayRepresentation: [UInt8] {
        var value: [UInt8] = []
        if let relyingPartyIDHash {
            value += relyingPartyIDHash
        }
        if let flags {
            value += [flags]
        }
        if let counter {
            value += counter
        }
        if let attestedCredData {
            value += attestedCredData
        }
        if let extensions {
            value += extensions
        }
        return value
    }
}

struct TestAuthDataBuilder {
    private var wrapped: TestAuthData

    init(wrapped: TestAuthData = TestAuthData()) {
        self.wrapped = wrapped
    }

    func build() -> TestAuthData {
        wrapped
    }

    func buildAsBase64URLEncoded() -> URLEncodedBase64 {
        build().byteArrayRepresentation.base64URLEncodedString()
    }

    func validMockECDSA() -> Self {
        self
            .relyingPartyIDHash(fromRelyingPartyID: "example.com")
            .flags(0b11000101)
            .counter([0b00000000, 0b00000000, 0b00000000, 0b00000000])
            .attestedCredData(
                credentialIDLength: [0b00000000, 0b00000001],
                credentialID: [0b00000001],
                credentialPublicKey: TestCredentialPublicKeyBuilder().validMockECDSA().buildAsByteArray()
            )
            .extensions([UInt8](repeating: 0, count: 20))
    }
    
    func validMockRSA() -> Self {
        self
            .relyingPartyIDHash(fromRelyingPartyID: "example.com")
            .flags(0b11000101)
            .counter([0b00000000, 0b00000000, 0b00000000, 0b00000000])
            .attestedCredData(
                credentialIDLength: [0b00000000, 0b00000001],
                credentialID: [0b00000001],
                credentialPublicKey: TestCredentialPublicKeyBuilder().validMockRSA().buildAsByteArray()
            )
            .extensions([UInt8](repeating: 0, count: 20))
    }

    /// Creates a valid authData
    ///
    /// relyingPartyID = "example.com", user
    /// flags "extension data included", "user verified" and "user present" are set
    /// sign count is set to 0
    /// random extension data is included
    func validAuthenticationMock() -> Self {
        self
            .relyingPartyIDHash(fromRelyingPartyID: "example.com")
            .flags(0b10000101)
            .counter([0b00000000, 0b00000000, 0b00000000, 0b00000000])
            .extensions([UInt8](repeating: 0, count: 20))
    }

    func relyingPartyIDHash(fromRelyingPartyID relyingPartyID: String) -> Self {
        let relyingPartyIDData = Data(relyingPartyID.utf8)
        let relyingPartyIDHash = SHA256.hash(data: relyingPartyIDData)
        var temp = self
        temp.wrapped.relyingPartyIDHash = [UInt8](relyingPartyIDHash)
        return temp
    }

    ///           ED AT __ BS BE UV __ UP
    /// e.g.: 0b  0  1  0  0  0  0  0  1
    func flags(_ byte: UInt8) -> Self {
        var temp = self
        temp.wrapped.flags = byte
        return temp
    }

    /// A valid counter has length 4
    func counter(_ counter: [UInt8]) -> Self {
        var temp = self
        temp.wrapped.counter = counter
        return temp
    }

    /// credentialIDLength length = 2
    /// credentialID length = credentialIDLength
    /// credentialPublicKey = variable
    func attestedCredData(
        authenticatorAttestationGUID: AAGUID = .anonymous,
        credentialIDLength: [UInt8] = [0b00000000, 0b00000001],
        credentialID: [UInt8] = [0b00000001],
        credentialPublicKey: [UInt8]
    ) -> Self {
        var temp = self
        temp.wrapped.attestedCredData = authenticatorAttestationGUID.bytes + credentialIDLength + credentialID + credentialPublicKey
        return temp
    }

    func noAttestedCredentialData() -> Self {
        var temp = self
        temp.wrapped.attestedCredData = nil
        return temp
    }

    func extensions(_ extensions: [UInt8]) -> Self {
        var temp = self
        temp.wrapped.extensions = extensions
        return temp
    }

    func noExtensionData() -> Self {
        var temp = self
        temp.wrapped.flags = temp.wrapped.flags.map{ $0 & 0b01111111 }
        temp.wrapped.extensions = nil
        return temp
    }
}

extension TestAuthData {
    static var valid: Self {
        TestAuthData(
            relyingPartyIDHash: [1],
            flags: 1,
            counter: [1],
            attestedCredData: [2],
            extensions: [1]
        )
    }
}
