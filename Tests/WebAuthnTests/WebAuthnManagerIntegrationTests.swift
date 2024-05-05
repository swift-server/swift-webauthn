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
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: "example.com",
            relyingPartyName: "Example RP",
            relyingPartyOrigin: "https://example.com"
        )

        let mockChallenge = [UInt8](repeating: 0, count: 5)
        let challengeGenerator = ChallengeGenerator(generate: { mockChallenge })
        let webAuthnManager = WebAuthnManager(configuration: configuration, challengeGenerator: challengeGenerator)

        // Step 1.: Begin Registration
        let mockUser = PublicKeyCredentialUserEntity.mock
        let timeout: Duration = .seconds(1234)
        let attestationPreference = AttestationConveyancePreference.none
        let publicKeyCredentialParameters: [PublicKeyCredentialParameters] = .supported

        let registrationOptions = webAuthnManager.beginRegistration(
            user: mockUser,
            timeout: timeout,
            attestation: attestationPreference,
            publicKeyCredentialParameters: publicKeyCredentialParameters
        )

        XCTAssertEqual(registrationOptions.challenge, mockChallenge)
        XCTAssertEqual(registrationOptions.user.id, mockUser.id)
        XCTAssertEqual(registrationOptions.user.name, mockUser.name)
        XCTAssertEqual(registrationOptions.user.displayName, mockUser.displayName)
        XCTAssertEqual(registrationOptions.attestation, attestationPreference)
        XCTAssertEqual(registrationOptions.relyingParty.id, configuration.relyingPartyID)
        XCTAssertEqual(registrationOptions.relyingParty.name, configuration.relyingPartyName)
        XCTAssertEqual(registrationOptions.timeout, timeout)
        XCTAssertEqual(registrationOptions.publicKeyCredentialParameters, publicKeyCredentialParameters)

        // Now send `registrationOptions` to client, which in turn will send the authenticator's response back to us:
        // The following lines reflect what an authenticator normally produces
        let mockCredentialID = [UInt8](repeating: 1, count: 10)
        let mockClientDataJSON = TestClientDataJSON(challenge: mockChallenge.base64URLEncodedString())
        let mockCredentialPublicKey = TestCredentialPublicKeyBuilder().validMock().buildAsByteArray()
        let mockAttestationObject = TestAttestationObjectBuilder().validMock().authData(
            TestAuthDataBuilder().validMock()
                .attestedCredData(credentialPublicKey: mockCredentialPublicKey)
                .noExtensionData()
        ).build().cborEncoded

        let registrationResponse = RegistrationCredential(
            id: mockCredentialID.base64URLEncodedString(),
            type: .publicKey,
            rawID: mockCredentialID,
            attestationResponse: AuthenticatorAttestationResponse(
                clientDataJSON: mockClientDataJSON.jsonBytes,
                attestationObject: mockAttestationObject
            )
        )

        // Step 2.: Finish Registration
        let credential = try await webAuthnManager.finishRegistration(
            challenge: mockChallenge,
            credentialCreationData: registrationResponse,
            requireUserVerification: true,
            supportedPublicKeyAlgorithms: publicKeyCredentialParameters,
            rootCertificatesByFormat: [:],
            confirmCredentialIDNotRegisteredYet: { _ in true }
        )

        XCTAssertEqual(credential.id, mockCredentialID.base64EncodedString().asString())
        XCTAssertEqual(credential.attestationClientDataJSON.type, .create)
        XCTAssertEqual(credential.attestationClientDataJSON.origin, mockClientDataJSON.origin)
        XCTAssertEqual(credential.attestationClientDataJSON.challenge, mockChallenge.base64URLEncodedString())
        XCTAssertEqual(credential.isBackedUp, false)
        XCTAssertEqual(credential.signCount, 0)
        XCTAssertEqual(credential.type, .publicKey)
        XCTAssertEqual(credential.publicKey, mockCredentialPublicKey)

        // Step 3.: Begin Authentication
        let authenticationTimeout: Duration = .seconds(4567)
        let userVerification: UserVerificationRequirement = .preferred
        let rememberedCredentials = [PublicKeyCredentialDescriptor(
            type: .publicKey,
            id: [UInt8](URLEncodedBase64(credential.id).urlDecoded.decoded!)
        )]

        let authenticationOptions = try webAuthnManager.beginAuthentication(
            timeout: authenticationTimeout,
            allowCredentials: rememberedCredentials,
            userVerification: userVerification
        )

        XCTAssertEqual(authenticationOptions.relyingPartyID, configuration.relyingPartyID)
        XCTAssertEqual(authenticationOptions.timeout, authenticationTimeout)
        XCTAssertEqual(authenticationOptions.challenge, mockChallenge)
        XCTAssertEqual(authenticationOptions.userVerification, userVerification)
        XCTAssertEqual(authenticationOptions.allowCredentials, rememberedCredentials)

        // Now send `authenticationOptions` to client, which in turn will send the authenticator's response back to us:
        // The following lines reflect what an authenticator normally produces
        let authenticatorData = TestAuthDataBuilder().validAuthenticationMock()
            .relyingPartyIDHash(fromRelyingPartyID: configuration.relyingPartyID)
            .counter([0, 0, 0, 1]) // we authenticated once now, so authenticator likely increments the sign counter
            .build()
            .byteArrayRepresentation

        // Authenticator creates a signature with private key

        // ATTENTION: It is very important that we encode `TestClientDataJSON` only once!!! Subsequent calls to
        // `jsonBytes` will result in different json (and thus the signature verification will fail)
        // This has already cost me hours of troubleshooting twice
        let clientData = TestClientDataJSON(
            type: "webauthn.get",
            challenge: mockChallenge.base64URLEncodedString()
        ).jsonBytes
        let clientDataHash = SHA256.hash(data: clientData)
        let signatureBase = Data(authenticatorData + clientDataHash)
        let signature = try TestECCKeyPair.signature(data: signatureBase).derRepresentation

        let authenticationCredential = AuthenticationCredential(
            id: mockCredentialID.base64URLEncodedString(),
            rawID: mockCredentialID,
            response: AuthenticatorAssertionResponse(
                clientDataJSON: clientData,
                authenticatorData: authenticatorData,
                signature: [UInt8](signature),
                userHandle: mockUser.id,
                attestationObject: nil
            ),
            authenticatorAttachment: .platform,
            type: .publicKey
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
        XCTAssertEqual(successfullAuthentication.credentialID, mockCredentialID.base64URLEncodedString())

        // We did it!
    }
}
