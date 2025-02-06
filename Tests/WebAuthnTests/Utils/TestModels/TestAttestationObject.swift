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

import WebAuthn
@preconcurrency import SwiftCBOR
import Testing

// protocol AttestationObjectParameter: CBOR {}

struct TestAttestationObject {
    var fmt: CBOR?
    var attStmt: CBOR?
    var authData: AuthData = .none
    
    enum AuthData {
        case structured(TestAuthData)
        case cbor(CBOR)
        case none
    }

    var cborEncoded: [UInt8] {
        var attestationObject: [CBOR: CBOR] = [:]
        if let fmt {
            attestationObject[.utf8String("fmt")] = fmt
        }
        if let attStmt {
            attestationObject[.utf8String("attStmt")] = attStmt
        }
        switch authData {
        case .structured(let authData):
            attestationObject[.utf8String("authData")] = .byteString(authData.byteArrayRepresentation)
        case .cbor(let authData):
            attestationObject[.utf8String("authData")] = authData
        case .none: break
        }

        return [UInt8](CBOR.map(attestationObject).encode())
    }
}

struct TestAttestationObjectBuilder {
    private var wrapped: TestAttestationObject

    init(wrapped: TestAttestationObject = TestAttestationObject()) {
        self.wrapped = wrapped
    }

    func keyAgnosticBase() -> Self {
        var temp = self
        temp.wrapped.fmt = .utf8String("none")
        temp.wrapped.attStmt = .map([:])
        return temp
    }

    func validMockECDSA() -> Self {
        var temp = self.keyAgnosticBase()
        temp.wrapped.authData = .structured(TestAuthDataBuilder().validMockECDSA().build())
        return temp
    }
    
    func validMockRSA() -> Self {
        var temp = self.keyAgnosticBase()
        temp.wrapped.authData = .structured(TestAuthDataBuilder().validMockRSA().build())
        return temp
    }

    func build() -> TestAttestationObject {
        return wrapped
    }

    func buildBase64URLEncoded() -> URLEncodedBase64 {
        build().cborEncoded.base64URLEncodedString()
    }

    // MARK: fmt

    func invalidFmt() -> Self {
        var temp = self
        temp.wrapped.fmt = .double(1)
        return temp
    }

    func fmt(_ utf8String: String) -> Self {
        var temp = self
        temp.wrapped.fmt = .utf8String(utf8String)
        return temp
    }

    // MARK: attStmt

    func invalidAttStmt() -> Self {
        var temp = self
        temp.wrapped.attStmt = .double(1)
        return temp
    }

    func attStmt(_ cbor: CBOR) -> Self {
        var temp = self
        temp.wrapped.attStmt = cbor
        return temp
    }

    func emptyAttStmt() -> Self {
        var temp = self
        temp.wrapped.attStmt = .map([:])
        return temp
    }

    func missingAttStmt() -> Self {
        var temp = self
        temp.wrapped.attStmt = nil
        return temp
    }

    // MARK: authData

    func invalidAuthData() -> Self {
        var temp = self
        temp.wrapped.authData = .cbor(.double(1))
        return temp
    }

    func emptyAuthData() -> Self {
        var temp = self
        temp.wrapped.authData = .cbor(.byteString([]))
        return temp
    }

    func zeroAuthData(byteCount: Int) -> Self {
        var temp = self
        temp.wrapped.authData = .cbor(.byteString([UInt8](repeating: 0, count: byteCount)))
        return temp
    }

    func authData(_ builder: TestAuthDataBuilder) -> Self {
        var temp = self
        temp.wrapped.authData = .structured(builder.build())
        return temp
    }
    
    func authData(builder: (TestAuthDataBuilder) -> TestAuthDataBuilder) -> Self {
        var temp = self
        switch temp.wrapped.authData {
        case .structured(let testAuthData):
            temp.wrapped.authData = .structured(builder(.init(wrapped: testAuthData)).build())
        case .cbor:
            Issue.record("authData must be structured")
        case .none:
            temp.wrapped.authData = .structured(builder(.init()).build())
        }
        return temp
    }

    // func authData(_ builder: )
}
