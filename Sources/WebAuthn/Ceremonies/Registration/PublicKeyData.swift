import Foundation
import SwiftCBOR
import Crypto

protocol PublicKeyData {
    /// The type of key created. Should be OKP, EC2, or RSA.
    var keyType: UInt64 { get }
    /// A COSEAlgorithmIdentifier for the algorithm used to derive the key signature.
    var algorithm: COSEAlgorithmIdentifier { get }
}

struct EC2PublicKeyData: PublicKeyData {
    let keyType: UInt64
    let algorithm: COSEAlgorithmIdentifier
    /// The curve on which we derive the signature from.
    let curve: UInt64
    /// A byte string 32 bytes in length that holds the x coordinate of the key.
    let xCoordinate: [UInt8]
    /// A byte string 32 bytes in length that holds the y coordinate of the key.
    let yCoordinate: [UInt8]

    func key() throws -> P256.Signing.PublicKey {
        switch algorithm {
        case .algES256:
            return try P256.Signing.PublicKey(rawRepresentation: xCoordinate + yCoordinate)
        }
    }

    init(from bytes: [UInt8]) throws {
        guard let publicKeyObject = try CBOR.decode(bytes) else { throw WebAuthnError.badRequestData }
        // This is now in COSE format
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        guard let keyTypeRaw = publicKeyObject[.unsignedInt(1)], case let .unsignedInt(keyType) = keyTypeRaw else {
            throw WebAuthnError.badRequestData
        }
        self.keyType = keyType

        guard let algorithmRaw = publicKeyObject[.unsignedInt(3)], case let .negativeInt(algorithmNegative) = algorithmRaw else {
            throw WebAuthnError.badRequestData
        }
        // https://github.com/unrelentingtech/SwiftCBOR#swiftcbor
        // Negative integers are decoded as NegativeInt(UInt), where the actual number is -1 - i
        guard let algorithm = COSEAlgorithmIdentifier(rawValue: -1 - Int(algorithmNegative)) else {
            throw WebAuthnError.unsupportedCOSEAlgorithm
        }
        self.algorithm = algorithm

        // Curve is key -1 - or -0 for SwiftCBOR
        // X Coordinate is key -2, or NegativeInt 1 for SwiftCBOR
        // Y Coordinate is key -3, or NegativeInt 2 for SwiftCBOR

        guard let curveRaw = publicKeyObject[.negativeInt(0)], case let .unsignedInt(curve) = curveRaw else {
            throw WebAuthnError.badRequestData
        }
        self.curve = curve

        guard let xCoordRaw = publicKeyObject[.negativeInt(1)], case let .byteString(xCoordinateBytes) = xCoordRaw else {
            throw WebAuthnError.badRequestData
        }
        self.xCoordinate = xCoordinateBytes
        guard let yCoordRaw = publicKeyObject[.negativeInt(2)], case let .byteString(yCoordinateBytes) = yCoordRaw else {
            throw WebAuthnError.badRequestData
        }
        self.yCoordinate = yCoordinateBytes
    }
}