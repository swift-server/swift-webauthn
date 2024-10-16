//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2023 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
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
            id: mockCredentialID,
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
            pemRootCertificatesByFormat: [:],
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
            id: mockCredentialID,
            authenticatorAttachment: .platform,
            response: AuthenticatorAssertionResponse(
                clientDataJSON: clientData,
                authenticatorData: authenticatorData,
                signature: [UInt8](signature),
                userHandle: mockUser.id,
                attestationObject: nil
            )
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
    
    func testClientRegistrationAndAuthentication() async throws {
        let challenge: [UInt8] = [1, 0, 1]
        let relyingPartyDisplayName = "Testy test"
        let relyingPartyID = "example.com"
        let relyingPartyOrigin = "https://example.com"
        
        let server = WebAuthnManager(
            configuration: .init(
                relyingPartyID: relyingPartyID,
                relyingPartyName: relyingPartyDisplayName,
                relyingPartyOrigin: relyingPartyOrigin
            ),
            challengeGenerator: .mock(generate: challenge)
        )
        
        let client = WebAuthnClient()
        let aaguid = AAGUID(uuid: UUID())
        let authenticator = KeyPairAuthenticator(attestationGloballyUniqueID: aaguid)
        
        let credentialCreationOptions = server.beginRegistration(user: .init(id: [1, 2, 3], name: "123", displayName: "One Two Three"))
        
        let (registrationCredential, credentialSource) = try await client.createRegistrationCredential(
            options: credentialCreationOptions,
            origin: relyingPartyOrigin,
            authenticator: authenticator
        )
        
        XCTAssertEqual(registrationCredential.type, .publicKey)
        XCTAssertEqual(registrationCredential.rawID.count, 16)
        XCTAssertEqual(registrationCredential.id, registrationCredential.rawID.base64URLEncodedString())
        
        let parsedAttestationResponse = try ParsedAuthenticatorAttestationResponse(from: registrationCredential.attestationResponse)
        XCTAssertEqual(parsedAttestationResponse.clientData.type, .create)
        XCTAssertEqual(parsedAttestationResponse.clientData.challenge.decodedBytes, [1, 0, 1])
        XCTAssertEqual(parsedAttestationResponse.clientData.origin, "https://example.com")
        
        XCTAssertEqual(parsedAttestationResponse.attestationObject.authenticatorData.relyingPartyIDHash, [163, 121, 166, 246, 238, 175, 185, 165, 94, 55, 140, 17, 128, 52, 226, 117, 30, 104, 47, 171, 159, 45, 48, 171, 19, 210, 18, 85, 134, 206, 25, 71])
        XCTAssertEqual(parsedAttestationResponse.attestationObject.authenticatorData.flags.bytes, [0b01011101])
        XCTAssertEqual(parsedAttestationResponse.attestationObject.authenticatorData.counter, 0)
        XCTAssertNotNil(parsedAttestationResponse.attestationObject.authenticatorData.attestedData)
        XCTAssertEqual(parsedAttestationResponse.attestationObject.authenticatorData.attestedData?.authenticatorAttestationGUID, AAGUID.anonymous)
        XCTAssertEqual(parsedAttestationResponse.attestationObject.authenticatorData.attestedData?.credentialID, credentialSource.id.bytes)
        XCTAssertEqual(parsedAttestationResponse.attestationObject.authenticatorData.extData, nil)
        
        let publicKey = try CredentialPublicKey(publicKeyBytes: parsedAttestationResponse.attestationObject.authenticatorData.attestedData?.publicKey ?? [])
        if case .ec2(let key) = publicKey {
            XCTAssertEqual(key.algorithm, .algES256)
            XCTAssertEqual(key.curve, .p256)
            XCTAssertEqual(key.xCoordinate.count, 32)
            XCTAssertEqual(key.yCoordinate.count, 32)
            XCTAssertEqual(key.rawRepresentation, (credentialSource.publicKey as? EC2PublicKey)?.rawRepresentation)
        } else {
            XCTFail("Unexpected publicKey format")
        }
        
        XCTAssertEqual(parsedAttestationResponse.attestationObject.format, .none)
        XCTAssertEqual(parsedAttestationResponse.attestationObject.attestationStatement, [:])
        
        XCTAssertEqual(credentialSource.relyingPartyID, "example.com")
        XCTAssertEqual(credentialSource.userHandle, [1, 2, 3])
        XCTAssertEqual(credentialSource.counter, 0)
        if case .es256(let privateKey) = credentialSource.key {
            XCTAssertEqual(Array(privateKey.publicKey.rawRepresentation), (credentialSource.publicKey as? EC2PublicKey)?.rawRepresentation)
        } else {
            XCTFail("Unexpected credentialSource.key format")
        }
        
        let registeredCredential = try await server.finishRegistration(
            challenge: challenge,
            credentialCreationData: registrationCredential
        ) { credentialID in
            XCTAssertEqual(credentialID, credentialSource.id.bytes.base64URLEncodedString().asString())
            return true
        }
        
        XCTAssertEqual(registeredCredential.type, .publicKey)
        XCTAssertEqual(registeredCredential.id, credentialSource.id.bytes.base64EncodedString().asString())
        XCTAssertEqual(registeredCredential.publicKey, (credentialSource.publicKey as? EC2PublicKey)?.bytes)
        XCTAssertEqual(registeredCredential.signCount, 0)
        XCTAssertEqual(registeredCredential.backupEligible, true)
        XCTAssertEqual(registeredCredential.isBackedUp, true)
        
        let credentialRequestOptions = try server.beginAuthentication()
        
        XCTAssertEqual(credentialRequestOptions.challenge, [1, 0, 1])
        XCTAssertEqual(credentialRequestOptions.timeout, .milliseconds(60000))
        XCTAssertEqual(credentialRequestOptions.relyingPartyID, "example.com")
        XCTAssertNil(credentialRequestOptions.allowCredentials)
        XCTAssertEqual(credentialRequestOptions.userVerification, .preferred)
        
        let (authenticationCredential, updatedCredentialSource) = try await client.assertAuthenticationCredential(
            options: credentialRequestOptions,
            origin: relyingPartyOrigin,
            authenticator: authenticator,
            credentialStore: [credentialSource.id : credentialSource]
        )
        
        XCTAssertEqual(authenticationCredential.type, .publicKey)
        XCTAssertEqual(authenticationCredential.rawID.count, 16)
        XCTAssertEqual(authenticationCredential.id, authenticationCredential.rawID.base64URLEncodedString())
        XCTAssertEqual(authenticationCredential.authenticatorAttachment, .platform)
        
        let parsedAssertionResponse = try ParsedAuthenticatorAssertionResponse(from: authenticationCredential.response)
        XCTAssertEqual(parsedAssertionResponse.clientData.type, .assert)
        XCTAssertEqual(parsedAssertionResponse.clientData.challenge.decodedBytes, [1, 0, 1])
        XCTAssertEqual(parsedAssertionResponse.clientData.origin, "https://example.com")
        
        XCTAssertEqual(parsedAssertionResponse.authenticatorData.relyingPartyIDHash, [163, 121, 166, 246, 238, 175, 185, 165, 94, 55, 140, 17, 128, 52, 226, 117, 30, 104, 47, 171, 159, 45, 48, 171, 19, 210, 18, 85, 134, 206, 25, 71])
        XCTAssertEqual(parsedAssertionResponse.authenticatorData.flags.bytes, [0b00011101])
        XCTAssertEqual(parsedAssertionResponse.authenticatorData.counter, 0)
        XCTAssertNil(parsedAssertionResponse.authenticatorData.attestedData)
        XCTAssertNil(parsedAssertionResponse.authenticatorData.extData)
        
        XCTAssertNotNil(parsedAssertionResponse.signature.decodedBytes)
        XCTAssertEqual(parsedAssertionResponse.userHandle, [1, 2, 3])
        
        XCTAssertEqual(credentialSource.id, updatedCredentialSource.id)
        XCTAssertEqual(updatedCredentialSource.relyingPartyID, "example.com")
        XCTAssertEqual(updatedCredentialSource.userHandle, [1, 2, 3])
        XCTAssertEqual(updatedCredentialSource.counter, 0)
        if case .es256(let privateKey) = updatedCredentialSource.key {
            XCTAssertEqual(Array(privateKey.publicKey.rawRepresentation), (updatedCredentialSource.publicKey as? EC2PublicKey)?.rawRepresentation)
        } else {
            XCTFail("Unexpected credentialSource.key format")
        }
        
        let verifiedAuthentication = try server.finishAuthentication(
            credential: authenticationCredential,
            expectedChallenge: challenge,
            credentialPublicKey: registeredCredential.publicKey, credentialCurrentSignCount: registeredCredential.signCount
        )
        
        XCTAssertEqual(verifiedAuthentication.credentialID.urlDecoded.asString(), registeredCredential.id)
        XCTAssertEqual(verifiedAuthentication.newSignCount, 0)
        XCTAssertEqual(verifiedAuthentication.credentialDeviceType, .multiDevice)
        XCTAssertEqual(verifiedAuthentication.credentialBackedUp, true)
    }
}
