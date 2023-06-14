//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2023 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@testable import WebAuthn
import XCTest
import Crypto

final class WebAuthnManagerIntegrationTests: XCTestCase {
    // swiftlint:disable:next function_body_length
    func testRegistrationAndAuthenticationSucceeds() async throws {
        let config = WebAuthnManager.Config(
            relyingPartyID: "example.com",
            relyingPartyName: "Example RP",
            relyingPartyOrigin: "https://example.com"
        )

        let mockChallenge = [UInt8](repeating: 0, count: 5)
        let challengeGenerator = ChallengeGenerator(generate: { mockChallenge })
        let webAuthnManager = WebAuthnManager(config: config, challengeGenerator: challengeGenerator)

        // Step 1.: Begin Registration
        let mockUser = PublicKeyCredentialUserEntity.mock
        let timeout: TimeInterval = 1234
        let attestationPreference = AttestationConveyancePreference.none
        let publicKeyCredentialParameters: [PublicKeyCredentialParameters] = .supported

        let registrationOptions = webAuthnManager.createRegistrationOptions(
            user: mockUser,
            timeoutInSeconds: timeout,
            attestation: attestationPreference,
            publicKeyCredentialParameters: publicKeyCredentialParameters
        )

        XCTAssertEqual(registrationOptions.challenge, mockChallenge)
        XCTAssertEqual(registrationOptions.user.id, mockUser.id)
        XCTAssertEqual(registrationOptions.user.name, mockUser.name)
        XCTAssertEqual(registrationOptions.user.displayName, mockUser.displayName)
        XCTAssertEqual(registrationOptions.attestation, attestationPreference)
        XCTAssertEqual(registrationOptions.relyingParty.id, config.relyingPartyID)
        XCTAssertEqual(registrationOptions.relyingParty.name, config.relyingPartyName)
        XCTAssertEqual(registrationOptions.timeoutInMilliseconds, UInt32(timeout * 1000))
        XCTAssertEqual(registrationOptions.publicKeyCredentialParameters, publicKeyCredentialParameters)

        // Now send `registrationOptions` to client, which in turn will send the authenticator's response back to us:
        // The following lines reflect what an authenticator normally produces
        let mockCredentialID = [UInt8](repeating: 1, count: 10).base64URLEncodedString()
        let mockClientDataJSON = TestClientDataJSON(challenge: mockChallenge.base64URLEncodedString())
        let mockCredentialPublicKey = TestCredentialPublicKeyBuilder().validMock().buildAsByteArray()
        let mockAttestationObject = TestAttestationObjectBuilder().validMock().authData(
            TestAuthDataBuilder().validMock()
                .attestedCredData(credentialPublicKey: mockCredentialPublicKey)
                .noExtensionData()
        )

        let registrationResponse = RegistrationCredential(
            id: mockCredentialID.asString(),
            type: "public-key",
            rawID: mockCredentialID,
            attestationResponse: AuthenticatorAttestationResponse(
                clientDataJSON: mockClientDataJSON.base64URLEncoded,
                attestationObject: mockAttestationObject.buildBase64URLEncoded()
            )
        )

        // Step 2.: Finish Registration
        let credential = try await webAuthnManager.finishRegistration(
            challenge: mockChallenge,
            credentialCreationData: registrationResponse,
            requireUserVerification: true,
            supportedPublicKeyAlgorithms: publicKeyCredentialParameters,
            pemRootCertificatesByFormat: [:],
            confirmCredentialIDNotRegisteredYet: { _ in true }
        )

        XCTAssertEqual(credential.id, mockCredentialID.asString())
        XCTAssertEqual(credential.attestationClientDataJSON.type, .create)
        XCTAssertEqual(credential.attestationClientDataJSON.origin, mockClientDataJSON.origin)
        XCTAssertEqual(credential.attestationClientDataJSON.challenge, mockChallenge.base64URLEncodedString())
        XCTAssertEqual(credential.isBackedUp, false)
        XCTAssertEqual(credential.signCount, 0)
        XCTAssertEqual(credential.type, "public-key")
        XCTAssertEqual(credential.publicKey, mockCredentialPublicKey)

        // Step 3.: Begin Authentication
        let authenticationTimeout: TimeInterval = 4567
        let userVerification: UserVerificationRequirement = .preferred
        let rememberedCredentials = [PublicKeyCredentialDescriptor(
            type: "public-key",
            id: [UInt8](URLEncodedBase64(credential.id).urlDecoded.decoded!)
        )]

        let authenticationOptions = try webAuthnManager.beginAuthentication(
            timeout: authenticationTimeout,
            allowCredentials: rememberedCredentials,
            userVerification: userVerification
        )

        XCTAssertEqual(authenticationOptions.rpId, config.relyingPartyID)
        XCTAssertEqual(authenticationOptions.timeout, UInt32(authenticationTimeout * 1000)) // timeout is in milliseconds
        XCTAssertEqual(authenticationOptions.challenge, mockChallenge)
        XCTAssertEqual(authenticationOptions.userVerification, userVerification)
        XCTAssertEqual(authenticationOptions.allowCredentials, rememberedCredentials)

        // Now send `authenticationOptions` to client, which in turn will send the authenticator's response back to us:
        // The following lines reflect what an authenticator normally produces
        let authenticatorData = TestAuthDataBuilder().validAuthenticationMock()
            .rpIDHash(fromRpID: config.relyingPartyID)
            .counter([0, 0, 0, 1]) // we authenticated once now, so authenticator likely increments the sign counter
            .buildAsBase64URLEncoded()

        // Authenticator creates a signature with private key
        let clientData: Data = TestClientDataJSON(
            type: "webauthn.get",
            challenge: mockChallenge.base64URLEncodedString()
        ).jsonData
        let clientDataHash = SHA256.hash(data: clientData)
        let rawAuthenticatorData = authenticatorData.urlDecoded.decoded!
        let signatureBase = rawAuthenticatorData + clientDataHash
        let signature = try TestECCKeyPair.signature(data: signatureBase).derRepresentation

        let authenticationCredential = AuthenticationCredential(
            id: mockCredentialID,
            response: AuthenticatorAssertionResponse(
                clientDataJSON: clientData.base64URLEncodedString(),
                authenticatorData: authenticatorData,
                signature: signature.base64URLEncodedString(),
                userHandle: mockUser.id,
                attestationObject: nil
            ),
            authenticatorAttachment: "platform",
            type: "public-key"
        )

        // Step 4.: Finish Authentication
        let oldSignCount: UInt32 = 0
        let successfullAuthentication = try webAuthnManager.finishAuthentication(
            credential: authenticationCredential,
            expectedChallenge: mockChallenge,
            credentialPublicKey: mockCredentialPublicKey,
            credentialCurrentSignCount: oldSignCount,
            requireUserVerification: false
        )

        XCTAssertEqual(successfullAuthentication.newSignCount, 1)
        XCTAssertEqual(successfullAuthentication.credentialBackedUp, false)
        XCTAssertEqual(successfullAuthentication.credentialDeviceType, .singleDevice)
        XCTAssertEqual(successfullAuthentication.credentialID, mockCredentialID)

        // We did it!
    }
}
