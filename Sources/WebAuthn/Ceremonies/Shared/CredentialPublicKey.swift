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

import Crypto
import _CryptoExtras
import Foundation
import SwiftCBOR

protocol PublicKey {
    var algorithm: COSEAlgorithmIdentifier { get }
    /// Verify a signature was signed with the private key corresponding to the public key.
    func verify(signature: Data, data: Data) throws
}

enum CredentialPublicKey {
    case okp(OKPPublicKey)
    case ec2(EC2PublicKey)
    case rsa(RSAPublicKeyData)

    var key: PublicKey {
        switch self {
        case let .okp(key):
            return key
        case let .ec2(key):
            return key
        case let .rsa(key):
            return key
        }
    }

    init(publicKeyBytes: [UInt8]) throws {
        guard let publicKeyObject = try CBOR.decode(publicKeyBytes) else {
            throw WebAuthnError.badPublicKeyBytes
        }

        // A leading 0x04 means we got a public key from an old U2F security key.
        // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats
        guard publicKeyBytes[0] != 0x04 else {
            self = .ec2(EC2PublicKey(
                algorithm: .algRS1,
                curve: .p256,
                xCoordinate: Data(Array(publicKeyBytes[1...33])),
                yCoordinate: Data(Array(publicKeyBytes[33...65]))
            ))
            return
        }

        guard let keyTypeRaw = publicKeyObject[COSEKey.kty.cbor],
            case let .unsignedInt(keyTypeInt) = keyTypeRaw,
            let keyType = COSEKeyType(rawValue: keyTypeInt) else {
            throw WebAuthnError.invalidKeyType
        }

        guard let algorithmRaw = publicKeyObject[COSEKey.alg.cbor],
            case let .negativeInt(algorithmNegative) = algorithmRaw else {
            throw WebAuthnError.invalidAlgorithm
        }
        // https://github.com/unrelentingtech/SwiftCBOR#swiftcbor
        // Negative integers are decoded as NegativeInt(UInt), where the actual number is -1 - i
        guard let algorithm = COSEAlgorithmIdentifier(rawValue: -1 - Int(algorithmNegative)) else {
            throw WebAuthnError.unsupportedCOSEAlgorithm
        }

        switch keyType {
        case .ellipticKey:
            self = try .ec2(EC2PublicKey(publicKeyObject: publicKeyObject, algorithm: algorithm))
        case .rsaKey:
            self = try .rsa(RSAPublicKeyData(publicKeyObject: publicKeyObject, algorithm: algorithm))
        case .octetKey:
            self = try .okp(OKPPublicKey(publicKeyObject: publicKeyObject, algorithm: algorithm))
        }
    }

    /// Verify a signature was signed with the private key corresponding to the provided public key.
    func verify(signature: Data, data: Data) throws {
        try key.verify(signature: signature, data: data)
    }
}

struct EC2PublicKey: PublicKey {
    let algorithm: COSEAlgorithmIdentifier
    /// The curve on which we derive the signature from.
    let curve: COSECurve
    /// A byte string 32 bytes in length that holds the x coordinate of the key.
    let xCoordinate: Data
    /// A byte string 32 bytes in length that holds the y coordinate of the key.
    let yCoordinate: Data

    var rawRepresentation: Data { xCoordinate + yCoordinate }

    init(algorithm: COSEAlgorithmIdentifier, curve: COSECurve, xCoordinate: Data, yCoordinate: Data) {
        self.algorithm = algorithm
        self.curve = curve
        self.xCoordinate = xCoordinate
        self.yCoordinate = yCoordinate
    }

    init(publicKeyObject: CBOR, algorithm: COSEAlgorithmIdentifier) throws {
        self.algorithm = algorithm

        // Curve is key -1 - or -0 for SwiftCBOR
        // X Coordinate is key -2, or NegativeInt 1 for SwiftCBOR
        // Y Coordinate is key -3, or NegativeInt 2 for SwiftCBOR
        guard let curveRaw = publicKeyObject[COSEKey.crv.cbor],
            case let .unsignedInt(curve) = curveRaw,
            let coseCurve = COSECurve(rawValue: curve) else {
            throw WebAuthnError.invalidCurve
        }
        self.curve = coseCurve

        guard let xCoordRaw = publicKeyObject[COSEKey.x.cbor],
              case let .byteString(xCoordinateBytes) = xCoordRaw else {
            throw WebAuthnError.invalidXCoordinate
        }
        xCoordinate = Data(xCoordinateBytes)
        guard let yCoordRaw = publicKeyObject[COSEKey.y.cbor],
              case let .byteString(yCoordinateBytes) = yCoordRaw else {
            throw WebAuthnError.invalidYCoordinate
        }
        yCoordinate = Data(yCoordinateBytes)
    }

    func verify(signature: Data, data: Data) throws {
        switch algorithm {
        case .algES256:
            let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
            guard try P256.Signing.PublicKey(rawRepresentation: rawRepresentation)
                .isValidSignature(ecdsaSignature, for: data) else {
                throw WebAuthnError.invalidSignature
            }
        case .algES384:
            let ecdsaSignature = try P384.Signing.ECDSASignature(derRepresentation: signature)
            guard try P384.Signing.PublicKey(rawRepresentation: rawRepresentation)
                .isValidSignature(ecdsaSignature, for: data) else {
                throw WebAuthnError.invalidSignature
            }
        case .algES512:
            let ecdsaSignature = try P521.Signing.ECDSASignature(derRepresentation: signature)
            guard try P521.Signing.PublicKey(rawRepresentation: rawRepresentation)
                .isValidSignature(ecdsaSignature, for: data) else {
                throw WebAuthnError.invalidSignature
            }
        default:
            throw WebAuthnError.unsupportedCOSEAlgorithmForEC2PublicKey
        }
    }
}

struct RSAPublicKeyData: PublicKey {
    let algorithm: COSEAlgorithmIdentifier
    // swiftlint:disable:next identifier_name
    let n: Data
    // swiftlint:disable:next identifier_name
    let e: Data

    var rawRepresentation: Data { n + e }

    init(publicKeyObject: CBOR, algorithm: COSEAlgorithmIdentifier) throws {
        self.algorithm = algorithm

        guard let nRaw = publicKeyObject[COSEKey.n.cbor],
              case let .byteString(nBytes) = nRaw else {
            throw WebAuthnError.invalidModulus
        }
        n = Data(nBytes)

        guard let eRaw = publicKeyObject[COSEKey.e.cbor],
              case let .byteString(eBytes) = eRaw else {
            throw WebAuthnError.invalidExponent
        }
        e = Data(eBytes)
    }

    func verify(signature: Data, data: Data) throws {
        let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation: signature)

        var rsaPadding: _RSA.Signing.Padding
        switch algorithm {
        case .algRS1, .algRS256, .algRS384, .algRS512:
            rsaPadding = .insecurePKCS1v1_5
        case .algPS256, .algPS384, .algPS512:
            rsaPadding = .PSS
        default:
            throw WebAuthnError.unsupportedCOSEAlgorithmForRSAPublicKey
        }

        guard try _RSA.Signing.PublicKey(derRepresentation: rawRepresentation).isValidSignature(
            rsaSignature,
            for: data,
            padding: rsaPadding
        ) else {
            throw WebAuthnError.invalidSignature
        }
    }
}

struct OKPPublicKey: PublicKey {
    let algorithm: COSEAlgorithmIdentifier
    let curve: UInt64
    let xCoordinate: [UInt8]

    init(publicKeyObject: CBOR, algorithm: COSEAlgorithmIdentifier) throws {
        self.algorithm = algorithm
        // Curve is key -1, or NegativeInt 0 for SwiftCBOR
        guard let curveRaw = publicKeyObject[.negativeInt(0)], case let .unsignedInt(curve) = curveRaw else {
            throw WebAuthnError.invalidCurve
        }
        self.curve = curve
        // X Coordinate is key -2, or NegativeInt 1 for SwiftCBOR
        guard let xCoordRaw = publicKeyObject[.negativeInt(1)],
            case let .byteString(xCoordinateBytes) = xCoordRaw else {
            throw WebAuthnError.invalidXCoordinate
        }
        xCoordinate = xCoordinateBytes
    }

    func verify(signature: Data, data: Data) throws {
        fatalError("OKPPublicKey not implemented yet")
    }
}
