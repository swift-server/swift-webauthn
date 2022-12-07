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
    public func beginRegistration(user: User) throws -> (PublicKeyCredentialCreationOptions, SessionData) {
        guard let base64ID = user.userID.data(using: .utf8)?.base64EncodedString() else {
            throw WebAuthnManagerError.base64EncodingFailed
        }

        let userEntity = PublicKeyCredentialUserEntity(name: user.name, id: base64ID, displayName: user.displayName)
        let relyingParty = PublicKeyCredentialRpEntity(name: config.relyingPartyDisplayName, id: config.relyingPartyID)

        let challenge = try generateChallengeString()

        let options = PublicKeyCredentialCreationOptions(
            challenge: challenge.base64EncodedString(),
            user: userEntity,
            relyingParty: relyingParty,
            publicKeyCredentialParameters: PublicKeyCredentialParameters.supported,
            timeout: config.timeout
        )
        let sessionData = SessionData(challenge: challenge.base64URLEncodedString(), userID: user.userID)

        return (options, sessionData)
    }

    /// Take response from authenticator and client and verify credential against the user's credentials and
    /// session data.
    /// - Parameters:
    ///   - user: The user to verify against the authenticator response
    ///   - sessionData: The data passed to the authenticator within the preceding registration options
    ///   - credentialCreationData: The value returned from `navigator.credentials.create()`
    ///   - requireUserVerification: Whether or not to require that the authenticator verified the user.
    /// - Returns:  A new `Credential` with information about the authenticator and registration
    public func finishRegistration(
        for user: User,
        sessionData: SessionData,
        credentialCreationData: CredentialCreationResponse,
        requireUserVerification: Bool = false,
        supportedPublicKeyAlgorithms: [PublicKeyCredentialParameters] = PublicKeyCredentialParameters.supported
    ) throws -> Credential {
        guard user.userID == sessionData.userID else { throw WebAuthnManagerError.userIDMismatch }

        let parsedData = try ParsedCredentialCreationResponse(from: credentialCreationData)
        try parsedData.verify(
            storedChallenge: sessionData.challenge,
            verifyUser: requireUserVerification,
            relyingPartyID: config.relyingPartyID,
            relyingPartyOrigin: config.relyingPartyOrigin
        )

        guard let attestedData = parsedData.response.attestationObject.authenticatorData.attestedData else {
            throw WebAuthnError.missingAttestedCredentialDataForCredentialCreateFlow
        }

        let credentialPublicKey = try CredentialPublicKey(fromPublicKeyBytes: attestedData.publicKey)
        try credentialPublicKey.verify(supportedPublicKeyAlgorithms: supportedPublicKeyAlgorithms)

        // TODO: Verify attStmt

        return Credential(
            id: attestedData.credentialID.base64URLEncodedString(),
            publicKey: attestedData.publicKey,
            attestationType: parsedData.response.attestationObject.format,
            authenticator: Authenticator(
                aaguid: attestedData.aaguid,
                signCount: parsedData.response.attestationObject.authenticatorData.counter
            )
        )
    }
}

extension WebAuthnManager {
    /// Generate a suitably random value to be used as an attestation or assertion challenge
    /// - Throws: An error if something went wrong while generating random byte
    /// - Returns: 32 bytes
    public func generateChallengeString() throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw WebAuthnManagerError.challengeGenerationFailed
        }
        return bytes
    }
}
