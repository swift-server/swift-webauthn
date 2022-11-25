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

import SwiftCBOR
import Crypto
import Logging
import Foundation

public enum WebAuthnManager {
    /// Generate a new set of registration data to be sent to the client and authenticator.
    public static func beginRegistration(user: User) throws -> (PublicKeyCredentialCreationOptions, SessionData) {
        let userEntity = PublicKeyCredentialUserEntity(name: user.name, id: user.id, displayName: user.displayName)
        let relyingParty = PublicKeyCredentialRpEntity(name: config.relyingPartyDisplayName, id: config.relyingPartyID)

        let challenge = try generateChallenge()

        let options = PublicKeyCredentialCreationOptions(
            challenge: challenge.base64EncodedString(),
            user: userEntity,
            relyingParty: relyingParty
        )
        let sessionData = SessionData(challenge: challenge.base64URLEncodedString(), userID: user.id)

        return (options, sessionData)
    }

    /// Verify that the user has legitimately completed the login process
    ///
    /// - Parameters:
    ///   - data: The response to verify
    ///   - expectedChallenge: The expected base64url-encoded challenge
    ///   - publicKey: The users public key
    ///   - logger: A logger
    /// - Throws:
    ///   - An error if the authentication response isn't valid
    public static func verifyAuthenticationResponse(
        _ data: AuthenticationResponse,
        expectedChallenge: String,
        publicKey: P256.Signing.PublicKey,
        // requireUserVerification: Bool = false
        logger: Logger
    ) throws {
        guard let clientObjectData = data.response.clientDataJSON.base64URLDecodedData else {
            throw WebAuthnError.badRequestData
        }
        let clientObject = try JSONDecoder().decode(ClientDataObject.self, from: clientObjectData)
        guard expectedChallenge == clientObject.challenge else {
            throw WebAuthnError.validationError
        }
        let clientDataJSONHash = SHA256.hash(data: clientObjectData)

        guard let authenticatorData = data.response.authenticatorData.base64URLDecodedData else {
            throw WebAuthnError.badRequestData
        }
        let signedData = authenticatorData + clientDataJSONHash

        guard let signatureData = data.response.signature.base64URLDecodedData else {
            throw WebAuthnError.badRequestData
        }
        let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
        guard publicKey.isValidSignature(signature, for: signedData) else {
            throw WebAuthnError.validationError
        }
    }

    public static func parseRegisterCredentials(
        _ data: RegistrationResponse,
        challengeProvided: String,
        origin: String,
        logger: Logger
    ) throws -> Credential {
        guard let clientObjectData = data.response.clientDataJSON.base64URLDecodedData else {
            throw WebAuthnError.badRequestData
        }
        let clientObject = try JSONDecoder().decode(ClientDataObject.self, from: clientObjectData)
        guard challengeProvided == clientObject.challenge else {
            throw WebAuthnError.validationError
        }
        guard clientObject.type == "webauthn.create" else {
            throw WebAuthnError.badRequestData
        }
        guard origin == clientObject.origin else {
            throw WebAuthnError.validationError
        }

        guard let attestationData = data.response.attestationObject.base64URLDecodedData else {
            throw WebAuthnError.badRequestData
        }
        guard let decodedAttestationObject = try CBOR.decode([UInt8](attestationData)) else {
            throw WebAuthnError.badRequestData
        }
        logger.debug("Got COBR decoded data: \(decodedAttestationObject)")

        // Ignore format/statement for now
        guard let authData = decodedAttestationObject["authData"], case let .byteString(authDataBytes) = authData else {
            throw WebAuthnError.badRequestData
        }
        guard let credentialsData = try parseAttestationObject(authDataBytes, logger: logger) else {
            throw WebAuthnError.badRequestData
        }
        guard let publicKeyObject = try CBOR.decode(credentialsData.publicKey) else {
            throw WebAuthnError.badRequestData
        }
        // This is now in COSE format
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        guard let keyTypeRaw = publicKeyObject[.unsignedInt(1)], case let .unsignedInt(keyType) = keyTypeRaw else {
            throw WebAuthnError.badRequestData
        }
        guard let algorithmRaw = publicKeyObject[.unsignedInt(3)], case let .negativeInt(algorithmNegative) = algorithmRaw else {
            throw WebAuthnError.badRequestData
        }
        // https://github.com/unrelentingtech/SwiftCBOR#swiftcbor
        // Negative integers are decoded as NegativeInt(UInt), where the actual number is -1 - i
        let algorithm: Int = -1 - Int(algorithmNegative)

        // Curve is key -1 - or -0 for SwiftCBOR
        // X Coordinate is key -2, or NegativeInt 1 for SwiftCBOR
        // Y Coordinate is key -3, or NegativeInt 2 for SwiftCBOR

        guard let curveRaw = publicKeyObject[.negativeInt(0)], case let .unsignedInt(curve) = curveRaw else {
            throw WebAuthnError.badRequestData
        }
        guard let xCoordRaw = publicKeyObject[.negativeInt(1)], case let .byteString(xCoordinateBytes) = xCoordRaw else {
            throw WebAuthnError.badRequestData
        }
        guard let yCoordRaw = publicKeyObject[.negativeInt(2)], case let .byteString(yCoordinateBytes) = yCoordRaw else {
            throw WebAuthnError.badRequestData
        }

        logger.debug("Key type was \(keyType)")
        logger.debug("Algorithm was \(algorithm)")
        logger.debug("Curve was \(curve)")

        let key = try P256.Signing.PublicKey(rawRepresentation: xCoordinateBytes + yCoordinateBytes)
        logger.debug("Key is \(key.pemRepresentation)")

        return Credential(credentialID: data.id, publicKey: key)
    }

    static func parseAttestedData(
        _ data: [UInt8],
        logger: Logger
    ) throws -> AttestedCredentialData {
        // We've parsed the first 37 bytes so far, the next bytes now should be the attested credential data
        // See https://w3c.github.io/webauthn/#sctn-attested-credential-data
        let aaguidLength = 16
        let aaguid = data[37..<(37 + aaguidLength)] // To byte at index 52

        let idLengthBytes = data[53..<55] // Length is 2 bytes
        let idLengthData = Data(idLengthBytes)
        let idLength: UInt16 = idLengthData.toInteger(endian: .big)
        let credentialIDEndIndex = Int(idLength) + 55

        let credentialID = data[55..<credentialIDEndIndex]
        let publicKeyBytes = data[credentialIDEndIndex...]

        return AttestedCredentialData(aaguid: Array(aaguid), credentialID: Array(credentialID), publicKey: Array(publicKeyBytes))
    }

    static func parseAttestationObject(
        _ bytes: [UInt8],
        logger: Logger
    ) throws -> AttestedCredentialData? {
        let minAuthDataLength = 37
        let minAttestedAuthLength = 55
        // TODO - fix
        // let maxCredentialIDLength = 1023
        // What to do when we don't have this
        var credentialsData: AttestedCredentialData? = nil

        guard bytes.count >= minAuthDataLength else {
            throw WebAuthnError.authDataTooShort
        }

        // TODO: Use
        // let rpIDHashData = bytes[..<32]
        let flags = AuthenticatorFlags(bytes[32])
        // TODO: Use
        // let counter: UInt32 = Data(bytes[33..<37]).toInteger(endian: .big)

        var remainingCount = bytes.count - minAuthDataLength

        if flags.attestedCredentialData {
            guard bytes.count > minAttestedAuthLength else {
                throw WebAuthnError.attestedCredentialDataMissing
            }
            let attestedCredentialData = try parseAttestedData(bytes, logger: logger)
            // 2 is the bytes storing the size of the credential ID
            let credentialDataLength = attestedCredentialData.aaguid.count + 2 + attestedCredentialData.credentialID.count + attestedCredentialData.publicKey.count
            remainingCount -= credentialDataLength
            credentialsData = attestedCredentialData
        } else {
            if !flags.extensionDataIncluded && bytes.count != minAuthDataLength {
                throw WebAuthnError.attestedCredentialFlagNotSet
            }
        }

        if flags.extensionDataIncluded {
            guard remainingCount != 0 else {
                throw WebAuthnError.extensionDataMissing
            }
            let extensionData = bytes[(bytes.count - remainingCount)...]
            remainingCount -= extensionData.count
        }

        guard remainingCount == 0 else {
            throw WebAuthnError.leftOverBytes
        }
        return credentialsData
    }
}