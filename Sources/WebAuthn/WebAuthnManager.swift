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
        attestation: AttestationConveyancePreference = .none,
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
            rp: relyingParty,
            pubKeyCredParams: publicKeyCredentialParameters,
            timeout: config.timeout,
            attestation: attestation
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
        pemRootCertificatesByFormat: [AttestationFormat: [Data]] = [:],
        confirmCredentialIDNotRegisteredYet: (String) async throws -> Bool
    ) async throws -> Credential {
        let parsedData = try ParsedCredentialCreationResponse(from: credentialCreationData)
        let attestedCredentialData = try await parsedData.verify(
            storedChallenge: challenge.urlEncoded,
            verifyUser: requireUserVerification,
            relyingPartyID: config.relyingPartyID,
            relyingPartyOrigin: config.relyingPartyOrigin,
            supportedPublicKeyAlgorithms: supportedPublicKeyAlgorithms,
            pemRootCertificatesByFormat: pemRootCertificatesByFormat
        )

        // TODO: Step 18. -> Verify client extensions

        // Step 24.
        guard try await confirmCredentialIDNotRegisteredYet(parsedData.id) else {
            throw WebAuthnError.credentialIDAlreadyExists
        }

        // Step 25.
        return Credential(
            type: parsedData.type,
            id: parsedData.id,
            publicKey: attestedCredentialData.publicKey,
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
        userVerification: UserVerificationRequirement = .preferred
    ) throws -> PublicKeyCredentialRequestOptions {
        let challenge = challenge ?? challengeGenerator.generate().base64EncodedString()
        return PublicKeyCredentialRequestOptions(
            challenge: challenge,
            timeout: timeout,
            rpId: config.relyingPartyID,
            allowCredentials: allowCredentials,
            userVerification: userVerification
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
        guard credential.type == "public-key" else { throw WebAuthnError.invalidAssertionCredentialType }

        let parsedAssertion = try ParsedAuthenticatorAssertionResponse(from: credential.response)
        try parsedAssertion.verify(
            expectedChallenge: expectedChallenge,
            relyingPartyOrigin: config.relyingPartyOrigin,
            relyingPartyID: config.relyingPartyID,
            requireUserVerification: requireUserVerification,
            credentialPublicKey: credentialPublicKey,
            credentialCurrentSignCount: credentialCurrentSignCount
        )

        return VerifiedAuthentication(
            credentialID: credential.id,
            newSignCount: parsedAssertion.authenticatorData.counter,
            credentialDeviceType: parsedAssertion.authenticatorData.flags.deviceType,
            credentialBackedUp: parsedAssertion.authenticatorData.flags.isCurrentlyBackedUp
        )
    }
}
