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

import Crypto
import _CryptoExtras
import Foundation
import SwiftCBOR

protocol PublicKey: Sendable {
    var algorithm: COSEAlgorithmIdentifier { get }
    /// Verify a signature was signed with the private key corresponding to the public key.
    func verify(signature: some DataProtocol, data: some DataProtocol) throws
}

enum CredentialPublicKey: Sendable {
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
        guard let publicKeyObject = try CBOR.decode(publicKeyBytes, options: CBOROptions(maximumDepth: 16)) else {
            throw WebAuthnError.badPublicKeyBytes
        }

        // A leading 0x04 means we got a public key from an old U2F security key.
        // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats
        guard publicKeyBytes[0] != 0x04 else {
            self = .ec2(EC2PublicKey(
                algorithm: .algES256,
                curve: .p256,
                xCoordinate: Array(publicKeyBytes[1...33]),
                yCoordinate: Array(publicKeyBytes[33...65])
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

        // Currently we only support elliptic curve algorithms
        switch keyType {
        case .ellipticKey:
            self = try .ec2(EC2PublicKey(publicKeyObject: publicKeyObject, algorithm: algorithm))
        case .rsaKey:
            self = try .rsa(RSAPublicKeyData(publicKeyObject: publicKeyObject, algorithm: algorithm))
        case .octetKey:
            throw WebAuthnError.unsupported
            // self = try .okp(OKPPublicKey(publicKeyObject: publicKeyObject, algorithm: algorithm))
        }
    }

    /// Verify a signature was signed with the private key corresponding to the provided public key.
    func verify(signature: some DataProtocol, data: some DataProtocol) throws {
        try key.verify(signature: signature, data: data)
    }
}

struct EC2PublicKey: PublicKey, Sendable {
    let algorithm: COSEAlgorithmIdentifier
    /// The curve on which we derive the signature from.
    let curve: COSECurve
    /// A byte string 32 bytes in length that holds the x coordinate of the key.
    let xCoordinate: [UInt8]
    /// A byte string 32 bytes in length that holds the y coordinate of the key.
    let yCoordinate: [UInt8]

    var rawRepresentation: [UInt8] { xCoordinate + yCoordinate }

    init(algorithm: COSEAlgorithmIdentifier, curve: COSECurve, xCoordinate: [UInt8], yCoordinate: [UInt8]) {
        self.algorithm = algorithm
        self.curve = curve
        self.xCoordinate = xCoordinate
        self.yCoordinate = yCoordinate
    }

    init(publicKeyObject: CBOR, algorithm: COSEAlgorithmIdentifier) throws(WebAuthnError) {
        self.algorithm = algorithm

        // Curve is key -1 - or -0 for SwiftCBOR
        // X Coordinate is key -2, or NegativeInt 1 for SwiftCBOR
        // Y Coordinate is key -3, or NegativeInt 2 for SwiftCBOR
        guard let curveRaw = publicKeyObject[COSEKey.crv.cbor],
            case let .unsignedInt(curve) = curveRaw,
            let coseCurve = COSECurve(rawValue: curve) else {
            throw .invalidCurve
        }
        self.curve = coseCurve

        guard let xCoordRaw = publicKeyObject[COSEKey.x.cbor],
              case let .byteString(xCoordinateBytes) = xCoordRaw else {
            throw .invalidXCoordinate
        }
        xCoordinate = xCoordinateBytes
        guard let yCoordRaw = publicKeyObject[COSEKey.y.cbor],
              case let .byteString(yCoordinateBytes) = yCoordRaw else {
            throw .invalidYCoordinate
        }
        yCoordinate = yCoordinateBytes
    }

    func verify(signature: some DataProtocol, data: some DataProtocol) throws {
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
            throw WebAuthnError.unsupportedCredentialPublicKeyAlgorithm
        }
    }
}

struct RSAPublicKeyData: PublicKey, Sendable {
    let algorithm: COSEAlgorithmIdentifier
    // swiftlint:disable:next identifier_name
    let n: [UInt8]
    // swiftlint:disable:next identifier_name
    let e: [UInt8]

    var rawRepresentation: [UInt8] { n + e }

    init(publicKeyObject: CBOR, algorithm: COSEAlgorithmIdentifier) throws(WebAuthnError) {
        self.algorithm = algorithm

        guard let nRaw = publicKeyObject[COSEKey.n.cbor],
              case let .byteString(nBytes) = nRaw else {
            throw .invalidModulus
        }
        n = nBytes

        guard let eRaw = publicKeyObject[COSEKey.e.cbor],
              case let .byteString(eBytes) = eRaw else {
            throw .invalidExponent
        }
        e = eBytes
    }

    func verify(signature: some DataProtocol, data: some DataProtocol) throws {
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

        let publicKey = try _RSA.Signing.PublicKey(n: n, e: e)
        guard publicKey.isValidSignature(rsaSignature, for: data, padding: rsaPadding)
        else { throw WebAuthnError.invalidSignature }
    }
}

/// Currently not in use
struct OKPPublicKey: PublicKey, Sendable {
    let algorithm: COSEAlgorithmIdentifier
    let curve: UInt64
    let xCoordinate: [UInt8]

    init(publicKeyObject: CBOR, algorithm: COSEAlgorithmIdentifier) throws(WebAuthnError) {
        self.algorithm = algorithm
        // Curve is key -1, or NegativeInt 0 for SwiftCBOR
        guard let curveRaw = publicKeyObject[.negativeInt(0)], case let .unsignedInt(curve) = curveRaw else {
            throw .invalidCurve
        }
        self.curve = curve
        // X Coordinate is key -2, or NegativeInt 1 for SwiftCBOR
        guard let xCoordRaw = publicKeyObject[.negativeInt(1)],
            case let .byteString(xCoordinateBytes) = xCoordRaw else {
            throw .invalidXCoordinate
        }
        xCoordinate = xCoordinateBytes
    }

    func verify(signature: some DataProtocol, data: some DataProtocol) throws {
        throw WebAuthnError.unsupported
    }
}
