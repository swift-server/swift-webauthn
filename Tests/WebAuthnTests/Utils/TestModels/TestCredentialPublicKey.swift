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

@testable import WebAuthn
import SwiftCBOR

struct TestCredentialPublicKey {
    var kty: CBOR?
    var alg: CBOR?
    var crv: CBOR?
    var xCoordinate: CBOR?
    var yCoordinate: CBOR?

    var byteArrayRepresentation: [UInt8] {
        var value: [CBOR: CBOR] = [:]
        if let kty {
            value[COSEKey.kty.cbor] = kty
        }
        if let alg {
            value[COSEKey.alg.cbor] = alg
        }
        if let crv {
            value[COSEKey.crv.cbor] = crv
        }
        if let xCoordinate {
            value[COSEKey.x.cbor] = xCoordinate
        }
        if let yCoordinate {
            value[COSEKey.y.cbor] = yCoordinate
        }
        return CBOR.map(value).encode()
    }
}

struct TestCredentialPublicKeyBuilder {
    var wrapped: TestCredentialPublicKey

    init(wrapped: TestCredentialPublicKey = TestCredentialPublicKey()) {
        self.wrapped = wrapped
    }

    func buildAsByteArray() -> [UInt8] {
        return wrapped.byteArrayRepresentation
    }

    func validMock() -> Self {
        return self
            .kty(.ellipticKey)
            .crv(.p256)
            .alg(.algES256)
            .xCoordinate(TestECCKeyPair.publicKeyXCoordinate)
            .yCoordiante(TestECCKeyPair.publicKeyYCoordinate)
    }

    func kty(_ kty: COSEKeyType) -> Self {
        var temp = self
        temp.wrapped.kty = .unsignedInt(kty.rawValue)
        return temp
    }

    func crv(_ crv: COSECurve) -> Self {
        var temp = self
        temp.wrapped.crv = .unsignedInt(crv.rawValue)
        return temp
    }

    func alg(_ alg: COSEAlgorithmIdentifier) -> Self {
        var temp = self
        temp.wrapped.alg = .negativeInt(UInt64(abs(alg.rawValue) - 1))
        return temp
    }

    func xCoordinate(_ xCoordinate: [UInt8]) -> Self {
        var temp = self
        temp.wrapped.xCoordinate = .byteString(xCoordinate)
        return temp
    }

    func yCoordiante(_ yCoordinate: [UInt8]) -> Self {
        var temp = self
        temp.wrapped.yCoordinate = .byteString(yCoordinate)
        return temp
    }
}
