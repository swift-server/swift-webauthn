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
import Logging
import SwiftCBOR

public struct WebAuthnManager {
    enum WebAuthnManagerError: Error {
        case base64EncodingFailed
        case challengeGenerationFailed
        case userIDMismatch
    }
    private let config: WebAuthnConfig

    public init(config: WebAuthnConfig) {
        self.config = config
    }

    /// Generate a new set of registration data to be sent to the client and authenticator.
    public func beginRegistration(user: User) throws -> PublicKeyCredentialCreationOptions {
        guard let base64ID = user.userID.data(using: .utf8)?.base64EncodedString() else {
            throw WebAuthnManagerError.base64EncodingFailed
        }

        let userEntity = PublicKeyCredentialUserEntity(name: user.name, id: base64ID, displayName: user.displayName)
        let relyingParty = PublicKeyCredentialRpEntity(name: config.relyingPartyDisplayName, id: config.relyingPartyID)

        let challenge = try generateChallengeString()

        return PublicKeyCredentialCreationOptions(
            challenge: challenge.base64EncodedString(),
            user: userEntity,
            relyingParty: relyingParty,
            publicKeyCredentialParameters: PublicKeyCredentialParameters.supported,
            timeout: config.timeout
        )
    }

    /// Take response from authenticator and client and verify credential against the user's credentials and
    /// session data.
    /// - Parameters:
    ///   - challenge: The user to verify against the authenticator response. Base64 encoded.
    ///   - credentialCreationData: The value returned from `navigator.credentials.create()`
    ///   - requireUserVerification: Whether or not to require that the authenticator verified the user.
    /// - Returns:  A new `Credential` with information about the authenticator and registration
    public func finishRegistration(
        challenge: EncodedBase64,
        credentialCreationData: RegistrationResponse,
        requireUserVerification: Bool = false,
        supportedPublicKeyAlgorithms: [PublicKeyCredentialParameters] = PublicKeyCredentialParameters.supported,
        confirmCredentialIDNotRegisteredYet: (String) async throws -> Bool
    ) async throws -> Credential {
        // Step 3. - 16.
        let parsedData = try ParsedCredentialCreationResponse(from: credentialCreationData)
        try parsedData.verify(
            storedChallenge: String.base64URL(fromBase64: challenge),
            verifyUser: requireUserVerification,
            relyingPartyID: config.relyingPartyID,
            relyingPartyOrigin: config.relyingPartyOrigin
        )

        guard let attestedData = parsedData.response.attestationObject.authenticatorData.attestedData else {
            throw WebAuthnError.missingAttestedCredentialData
        }

        // Step 17.
        let credentialPublicKey = try CredentialPublicKey(publicKeyBytes: attestedData.publicKey)
        guard supportedPublicKeyAlgorithms.map(\.algorithm).contains(credentialPublicKey.key.algorithm) else {
            throw WebAuthnError.unsupportedCredentialPublicKeyAlgorithm
        }

        // TODO: Step 18. -> Verify client extensions

        // Step 24.
        guard try await confirmCredentialIDNotRegisteredYet(parsedData.id) else {
            throw WebAuthnError.credentialIDAlreadyExists
        }

        // Step 25.
        return Credential(
            type: parsedData.type,
            id: parsedData.id,
            publicKey: attestedData.publicKey,
            signCount: parsedData.response.attestationObject.authenticatorData.counter,
            backupEligible: parsedData.response.attestationObject.authenticatorData.flags.isBackupEligible,
            isBackedUp: parsedData.response.attestationObject.authenticatorData.flags.isCurrentlyBackedUp,
            attestationObject: parsedData.response.attestationObject,
            attestationClientDataJSON: parsedData.response.clientData
        )
    }

    public func beginAuthentication(
        challenge: String? = nil,
        timeout: TimeInterval?,
        allowCredentials: [PublicKeyCredentialDescriptor]? = nil,
        userVerification: UserVerificationRequirement = .preferred,
        attestation: String? = nil,
        attestationFormats: [String]? = nil
    ) throws -> PublicKeyCredentialRequestOptions {
        let challenge = try challenge ?? generateChallengeString().base64EncodedString()
        return PublicKeyCredentialRequestOptions(
            challenge: challenge,
            timeout: timeout,
            rpId: config.relyingPartyID,
            allowCredentials: allowCredentials,
            userVerification: userVerification,
            attestation: attestation,
            attestationFormats: attestationFormats
        )
    }

    public func finishAuthentication(
        credential: AuthenticationCredential,
        // clientExtensionResults: ,
        expectedChallenge: URLEncodedBase64,
        credentialPublicKey: [UInt8],
        credentialCurrentSignCount: Int,
        requireUserVerification: Bool = false
    ) throws -> VerifiedAuthentication {
        let expectedRpID = config.relyingPartyID
        guard credential.type == "public-key" else { throw WebAuthnError.badRequestData }

        let response = credential.response

        guard let clientDataData = response.clientDataJSON.base64URLDecodedData else {
            throw WebAuthnError.badRequestData
        }
        let clientData = try JSONDecoder().decode(CollectedClientData.self, from: clientDataData)
        try clientData.verify(
            storedChallenge: expectedChallenge,
            ceremonyType: .assert,
            relyingPartyOrigin: config.relyingPartyOrigin
        )
        // TODO: - Verify token binding

        guard let authenticatorDataBytes = response.authenticatorData.base64URLDecodedData else {
            throw WebAuthnError.badRequestData
        }
        let authenticatorData = try AuthenticatorData(bytes: authenticatorDataBytes)

        guard let expectedRpIDData = expectedRpID.data(using: .utf8) else { throw WebAuthnError.badRequestData }
        let expectedRpIDHash = SHA256.hash(data: expectedRpIDData)
        guard expectedRpIDHash == authenticatorData.relyingPartyIDHash else { throw WebAuthnError.badRequestData }

        guard authenticatorData.flags.userPresent else { throw WebAuthnError.badRequestData }
        if requireUserVerification {
            guard authenticatorData.flags.userVerified else { throw WebAuthnError.badRequestData }
        }

        if authenticatorData.counter > 0 || credentialCurrentSignCount > 0 {
            guard authenticatorData.counter > credentialCurrentSignCount else { throw WebAuthnError.badRequestData }
        }

        let clientDataHash = SHA256.hash(data: clientDataData)
        let signatureBase = authenticatorDataBytes + clientDataHash

        let credentialPublicKey = try CredentialPublicKey(publicKeyBytes: credentialPublicKey)
        guard let signatureData = response.signature.base64URLDecodedData else { throw WebAuthnError.badRequestData }
        try credentialPublicKey.verify(signature: signatureData, data: signatureBase)

        return VerifiedAuthentication(
            credentialID: credential.id,
            newSignCount: authenticatorData.counter,
            credentialDeviceType: authenticatorData.flags.isBackupEligible ? .multiDevice : .singleDevice,
            credentialBackedUp: authenticatorData.flags.isCurrentlyBackedUp
        )
    }
}

extension WebAuthnManager {
    /// Generate a suitably random value to be used as an attestation or assertion challenge
    /// - Throws: An error if something went wrong while generating random byte
    /// - Returns: 32 bytes
    public func generateChallengeString() throws -> [UInt8] {
        [UInt8].random(count: 32)
    }
}
