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

@testable import WebAuthn
import XCTest

final class WebAuthnManagerIntegrationTests: XCTestCase {
    // swiftlint:disable:next function_body_length
    func testRegistrationAndAuthenticationWorks() async throws {
        let config = WebAuthnConfig(
            relyingPartyDisplayName: "Example RP",
            relyingPartyID: "example.com",
            relyingPartyOrigin: "https://example.com"
        )

        let mockChallenge = [UInt8](repeating: 0, count: 5)
        let challengeGenerator = ChallengeGenerator(generate: { mockChallenge })
        let webAuthnManager = WebAuthnManager(config: config, challengeGenerator: challengeGenerator)

        // Step 1.: Begin Registration
        let mockUser = MockUser()
        let timeout: TimeInterval = 1234
        let publicKeyCredentialParameters = PublicKeyCredentialParameters.supported

        let registrationOptions = try webAuthnManager.beginRegistration(
            user: mockUser,
            timeout: timeout,
            publicKeyCredentialParameters: publicKeyCredentialParameters
        )

        XCTAssertEqual(registrationOptions.challenge, mockChallenge.base64EncodedString())
        XCTAssertEqual(registrationOptions.user.id, mockUser.userID.toBase64().asString())
        XCTAssertEqual(registrationOptions.user.name, mockUser.name)
        XCTAssertEqual(registrationOptions.user.displayName, mockUser.displayName)
        XCTAssertEqual(registrationOptions.attestation, .none)
        XCTAssertEqual(registrationOptions.rp.id, config.relyingPartyID)
        XCTAssertEqual(registrationOptions.rp.name, config.relyingPartyDisplayName)
        XCTAssertEqual(registrationOptions.timeout, timeout)
        XCTAssertEqual(registrationOptions.pubKeyCredParams, publicKeyCredentialParameters)

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
        let requireUserVerification = true

        let credential = try await webAuthnManager.finishRegistration(
            challenge: mockChallenge.base64EncodedString(),
            credentialCreationData: registrationResponse,
            requireUserVerification: requireUserVerification,
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
        XCTAssertEqual(credential.publicKey, mockCredentialPublicKey)
    }
}
