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

@testable import WebAuthn
import SwiftCBOR

struct TestCredentialPublicKey {
    var kty: CBOR?
    var alg: CBOR?
    var crv: CBOR?
    var xCoordinate: CBOR?
    var yCoordinate: CBOR?

    var byteArrayRepresentation: [UInt8] {
        var value: [(COSEKey, CBOR)] = []
        if let kty {
            value.append((COSEKey.kty, kty))
        }
        if let alg {
            value.append((COSEKey.alg, alg))
        }
        if let crv {
            value.append((COSEKey.crv, crv))
        }
        if let xCoordinate {
            value.append((COSEKey.x, xCoordinate))
        }
        if let yCoordinate {
            value.append((COSEKey.y, yCoordinate))
        }
        return CBOR.encodeSortedPairs(value)
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
