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
import Foundation
import SwiftCBOR

protocol PublicKey {
    func getString() throws -> String
}

struct CredentialPublicKey {
    /// The type of key created. Should be OKP, EC2, or RSA.
    let keyType: COSEKeyType
    /// A COSEAlgorithmIdentifier for the algorithm used to derive the key signature.
    let algorithm: COSEAlgorithmIdentifier

    private let publicKeyObject: CBOR

    init(fromPublicKeyBytes publicKeyBytes: [UInt8]) throws {
        guard let publicKeyObject = try CBOR.decode(publicKeyBytes) else {
            throw WebAuthnError.badRequestData
        }
        self.publicKeyObject = publicKeyObject

        guard let keyTypeRaw = publicKeyObject[.unsignedInt(1)],
            case let .unsignedInt(keyTypeInt) = keyTypeRaw,
            let keyType = COSEKeyType(rawValue: keyTypeInt) else {
            throw WebAuthnError.badRequestData
        }
        self.keyType = keyType

        guard let algorithmRaw = publicKeyObject[.unsignedInt(3)],
            case let .negativeInt(algorithmNegative) = algorithmRaw else {
            throw WebAuthnError.badRequestData
        }
        // https://github.com/unrelentingtech/SwiftCBOR#swiftcbor
        // Negative integers are decoded as NegativeInt(UInt), where the actual number is -1 - i
        guard let algorithm = COSEAlgorithmIdentifier(rawValue: -1 - Int(algorithmNegative)) else {
            throw WebAuthnError.unsupportedCOSEAlgorithm
        }
        self.algorithm = algorithm
    }

    func verify(supportedPublicKeyAlgorithms: [PublicKeyCredentialParameters]) throws  {
        // Step 17.
        guard supportedPublicKeyAlgorithms.map(\.algorithm).contains(algorithm) else {
            throw WebAuthnError.unsupportedCredentialPublicKeyAlgorithm
        }
    }

    func getPublicKey() throws -> PublicKey {
        switch keyType {
        case .ellipticKey:
            return try EC2PublicKey(publicKeyObject: publicKeyObject, algorithm: algorithm)
        case .rsaKey:
            return try RSAPublicKeyData(publicKeyObject: publicKeyObject, algorithm: algorithm)
        case .octetKey:
            return try OKPPublicKey(publicKeyObject: publicKeyObject, algorithm: algorithm)
        }
    }
}

struct EC2PublicKey: PublicKey {
    let algorithm: COSEAlgorithmIdentifier
    /// The curve on which we derive the signature from.
    let curve: UInt64
    /// A byte string 32 bytes in length that holds the x coordinate of the key.
    let xCoordinate: [UInt8]
    /// A byte string 32 bytes in length that holds the y coordinate of the key.
    let yCoordinate: [UInt8]

    init(publicKeyObject: CBOR, algorithm: COSEAlgorithmIdentifier) throws {
        self.algorithm = algorithm

        // Curve is key -1 - or -0 for SwiftCBOR
        // X Coordinate is key -2, or NegativeInt 1 for SwiftCBOR
        // Y Coordinate is key -3, or NegativeInt 2 for SwiftCBOR
        guard let curveRaw = publicKeyObject[.negativeInt(0)], case let .unsignedInt(curve) = curveRaw else {
            throw WebAuthnError.badRequestData
        }
        self.curve = curve

        guard let xCoordRaw = publicKeyObject[.negativeInt(1)],
              case let .byteString(xCoordinateBytes) = xCoordRaw else {
            throw WebAuthnError.badRequestData
        }
        xCoordinate = xCoordinateBytes
        guard let yCoordRaw = publicKeyObject[.negativeInt(2)],
              case let .byteString(yCoordinateBytes) = yCoordRaw else {
            throw WebAuthnError.badRequestData
        }
        yCoordinate = yCoordinateBytes
    }

    func getString() throws -> String {
        let rawRepresentation = xCoordinate + yCoordinate
        switch algorithm {
        case .algES256:
            return try P256.Signing.PublicKey(rawRepresentation: rawRepresentation).pemRepresentation
        case .algES384:
            return try P384.Signing.PublicKey(rawRepresentation: rawRepresentation).pemRepresentation
        case .algES512:
            return try P521.Signing.PublicKey(rawRepresentation: rawRepresentation).pemRepresentation
        default:
            throw WebAuthnError.unsupportedCOSEAlgorithm
        }
    }
}

struct RSAPublicKeyData: PublicKey {
    let algorithm: COSEAlgorithmIdentifier
    // swiftlint:disable:next identifier_name
    let n: [UInt8]
    // swiftlint:disable:next identifier_name
    let e: [UInt8]

    init(publicKeyObject: CBOR, algorithm: COSEAlgorithmIdentifier) throws {
        self.algorithm = algorithm

        guard let nRaw = publicKeyObject[.negativeInt(0)],
              case let .byteString(nBytes) = nRaw else {
            throw WebAuthnError.badRequestData
        }
        n = nBytes

        guard let eRaw = publicKeyObject[.negativeInt(1)],
              case let .byteString(eBytes) = eRaw else {
            throw WebAuthnError.badRequestData
        }
        e = eBytes
    }

    func getString() throws -> String {
        // switch algorithm {
        // case .algRS1:
        //     return try RSA.
        // case .algRS256, .algPS256:
        //     return try
        // case .algRS384, .algPS384:
        //     return try
        // case .algRS512, case .algPS512:
        //     return try
        // default:
        //     throw WebAuthnError.unsupportedCOSEAlgorithm
        // }
        fatalError("RSA is currently not supported")
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
            throw WebAuthnError.badRequestData
        }
        self.curve = curve
        // X Coordinate is key -2, or NegativeInt 1 for SwiftCBOR
        guard let xCoordRaw = publicKeyObject[.negativeInt(1)],
            case let .byteString(xCoordinateBytes) = xCoordRaw else {
            throw WebAuthnError.badRequestData
        }
        xCoordinate = xCoordinateBytes
    }

    func getString() throws -> String {
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: xCoordinate)
        return String(data: key.rawRepresentation, encoding: .utf8)!
    }
}
