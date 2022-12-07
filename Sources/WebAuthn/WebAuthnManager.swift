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

    // Take response from authenticator and client and verify credential against the user's credentials and
    // session data.
    public func finishRegistration(
        for user: User,
        sessionData: SessionData,
        credentialCreationData: CredentialCreationResponse
    ) throws -> Credential {
        guard user.userID == sessionData.userID else { throw WebAuthnManagerError.userIDMismatch }

        // TODO: session.UserVerification == protocol.VerificationRequired

        let parsedData = try ParsedCredentialCreationResponse(from: credentialCreationData)

        try parsedData.verify(
            storedChallenge: sessionData.challenge,
            verifyUser: false,  // TODO: Implement verifyUser
            relyingPartyID: config.relyingPartyID,
            relyingPartyOrigin: config.relyingPartyOrigin
        )

        return try Credential(from: parsedData)
    }
}

extension WebAuthnManager {
    /// Generate a suitably random value to be used as an attestation or assertion challenge
    /// - Throws: An error if something went wrong while generating random byte
    /// - Returns: 32 bytes
    public func generateChallengeString() throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw WebAuthnManagerError.challengeGenerationFailed }
        return bytes
    }
}
