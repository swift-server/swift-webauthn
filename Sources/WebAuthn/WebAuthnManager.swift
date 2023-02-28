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
    private let config: WebAuthnConfig

    private let challengeGenerator: ChallengeGenerator

    public init(config: WebAuthnConfig, challengeGenerator: ChallengeGenerator = .live) {
        self.config = config
        self.challengeGenerator = challengeGenerator
    }

    /// Generate a new set of registration data to be sent to the client and authenticator.
    public func beginRegistration(
        user: User,
        publicKeyCredentialParameters: [PublicKeyCredentialParameters] = PublicKeyCredentialParameters.supported
    ) throws -> PublicKeyCredentialCreationOptions {
        guard let base64ID = user.userID.data(using: .utf8)?.base64EncodedString() else {
            throw WebAuthnError.invalidUserID
        }

        let userEntity = PublicKeyCredentialUserEntity(name: user.name, id: base64ID, displayName: user.displayName)
        let relyingParty = PublicKeyCredentialRpEntity(name: config.relyingPartyDisplayName, id: config.relyingPartyID)

        let challenge = challengeGenerator.generate()

        return PublicKeyCredentialCreationOptions(
            challenge: challenge.base64EncodedString(),
            user: userEntity,
            relyingParty: relyingParty,
            publicKeyCredentialParameters: publicKeyCredentialParameters,
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
        credentialCreationData: RegistrationCredential,
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
            throw WebAuthnError.attestedCredentialDataMissing
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
        challenge: EncodedBase64? = nil,
        timeout: TimeInterval?,
        allowCredentials: [PublicKeyCredentialDescriptor]? = nil,
        userVerification: UserVerificationRequirement = .preferred,
        attestation: String? = nil,
        attestationFormats: [String]? = nil
    ) throws -> PublicKeyCredentialRequestOptions {
        let challenge = challenge ?? challengeGenerator.generate().base64EncodedString()
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
        guard credential.type == "public-key" else { throw WebAuthnError.invalidAssertionCredentialType }

        let response = credential.response

        guard let clientDataData = response.clientDataJSON.base64URLDecodedData else {
            throw WebAuthnError.invalidClientDataJSON
        }
        let clientData = try JSONDecoder().decode(CollectedClientData.self, from: clientDataData)
        try clientData.verify(
            storedChallenge: expectedChallenge,
            ceremonyType: .assert,
            relyingPartyOrigin: config.relyingPartyOrigin
        )
        // TODO: - Verify token binding

        guard let authenticatorDataBytes = response.authenticatorData.base64URLDecodedData else {
            throw WebAuthnError.invalidAuthenticatorData
        }
        let authenticatorData = try AuthenticatorData(bytes: authenticatorDataBytes)

        guard let expectedRpIDData = expectedRpID.data(using: .utf8) else { throw WebAuthnError.invalidRelyingPartyID }
        let expectedRpIDHash = SHA256.hash(data: expectedRpIDData)
        guard expectedRpIDHash == authenticatorData.relyingPartyIDHash else {
            throw WebAuthnError.relyingPartyIDHashDoesNotMatch
        }

        guard authenticatorData.flags.userPresent else { throw WebAuthnError.userPresentFlagNotSet }
        if requireUserVerification {
            guard authenticatorData.flags.userVerified else { throw WebAuthnError.userVerifiedFlagNotSet }
        }

        if authenticatorData.counter > 0 || credentialCurrentSignCount > 0 {
            guard authenticatorData.counter > credentialCurrentSignCount else {
                // This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential
                // private key may exist and are being used in parallel.
                throw WebAuthnError.potentialReplayAttack
            }
        }

        let clientDataHash = SHA256.hash(data: clientDataData)
        let signatureBase = authenticatorDataBytes + clientDataHash

        let credentialPublicKey = try CredentialPublicKey(publicKeyBytes: credentialPublicKey)
        guard let signatureData = response.signature.base64URLDecodedData else { throw WebAuthnError.invalidSignature }
        try credentialPublicKey.verify(signature: signatureData, data: signatureBase)

        return VerifiedAuthentication(
            credentialID: credential.id,
            newSignCount: authenticatorData.counter,
            credentialDeviceType: authenticatorData.flags.isBackupEligible ? .multiDevice : .singleDevice,
            credentialBackedUp: authenticatorData.flags.isCurrentlyBackedUp
        )
    }
}
