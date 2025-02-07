//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@testable import WebAuthn
import Testing
import Foundation
import SwiftCBOR
import Crypto

struct WebAuthnManagerAuthenticationTests {
    var webAuthnManager: WebAuthnManager!

    let challenge: [UInt8] = [1, 0, 1]
    let relyingPartyID = "example.com"
    let relyingPartyName = "Testy test"
    let relyingPartyOrigin = "https://example.com"

    init() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: relyingPartyID,
            relyingPartyName: relyingPartyName,
            relyingPartyOrigin: relyingPartyOrigin
        )
        webAuthnManager = .init(configuration: configuration, challengeGenerator: .mock(generate: challenge))
    }

    @Test
    func beginAuthentication() async throws {
        let allowCredentials: [PublicKeyCredentialDescriptor] = [.init(type: .publicKey, id: [1, 0, 2, 30])]
        let options = webAuthnManager.beginAuthentication(
            timeout: .seconds(1234),
            allowCredentials: allowCredentials,
            userVerification: .preferred
        )

        #expect(options.challenge == challenge)
        #expect(options.timeout == .seconds(1234))
        #expect(options.relyingPartyID == relyingPartyID)
        #expect(options.allowCredentials == allowCredentials)
        #expect(options.userVerification == .preferred)
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishAuthenticationFailsIfCredentialTypeIsInvalid(keyConfiguration: TestKeyConfiguration) throws {
        #expect(throws: WebAuthnError.invalidAssertionCredentialType) {
            try finishAuthentication(
                signature: keyConfiguration.signer.signature,
                type: "invalid",
                credentialPublicKey: keyConfiguration.credentialPublicKey
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishAuthenticationFailsIfClientDataJSONDecodingFails(keyConfiguration: TestKeyConfiguration) throws {
        #expect(throws: DecodingError.self) {
            try finishAuthentication(
                clientDataJSON: [0],
                signature: keyConfiguration.signer.signature,
                credentialPublicKey: keyConfiguration.credentialPublicKey
            )
        }
    }
    
    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishAuthenticationFailsIfCeremonyTypeDoesNotMatch(keyConfiguration: TestKeyConfiguration) throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.type = "webauthn.create"
        #expect(throws: CollectedClientData.CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch) {
            try finishAuthentication(
                clientDataJSON: clientDataJSON.jsonBytes,
                signature: keyConfiguration.signer.signature,
                credentialPublicKey: keyConfiguration.credentialPublicKey
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishAuthenticationFailsIfRelyingPartyIDHashDoesNotMatch(keyConfiguration: TestKeyConfiguration) throws {
        #expect(throws: WebAuthnError.relyingPartyIDHashDoesNotMatch) {
            try finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .relyingPartyIDHash(fromRelyingPartyID: "wrong-id.org")
                    .build()
                    .byteArrayRepresentation,
                signature: keyConfiguration.signer.signature,
                credentialPublicKey: keyConfiguration.credentialPublicKey
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishAuthenticationFailsIfUserPresentFlagIsNotSet(keyConfiguration: TestKeyConfiguration) throws {
        #expect(throws: WebAuthnError.userPresentFlagNotSet) {
            try finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .flags(0b10000000)
                    .build()
                    .byteArrayRepresentation,
                signature: keyConfiguration.signer.signature,
                credentialPublicKey: keyConfiguration.credentialPublicKey
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishAuthenticationFailsIfUserIsNotVerified(keyConfiguration: TestKeyConfiguration) throws {
        #expect(throws: WebAuthnError.userVerifiedFlagNotSet) {
            try finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .flags(0b10000001)
                    .build()
                    .byteArrayRepresentation,
                signature: keyConfiguration.signer.signature,
                credentialPublicKey: keyConfiguration.credentialPublicKey,
                requireUserVerification: true
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishAuthenticationFailsIfCredentialCounterIsNotUpToDate(keyConfiguration: TestKeyConfiguration) throws {
        #expect(throws: WebAuthnError.potentialReplayAttack) {
            try finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .counter([0, 0, 0, 1]) // signCount = 1
                    .build()
                    .byteArrayRepresentation,
                signature: keyConfiguration.signer.signature,
                credentialPublicKey: keyConfiguration.credentialPublicKey,
                credentialCurrentSignCount: 2
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishAuthenticationSucceeds(keyConfiguration: TestKeyConfiguration) throws {
        let credentialID = TestConstants.mockCredentialID
        let oldSignCount: UInt32 = 0

        let authenticatorData = TestAuthDataBuilder()
                .validAuthenticationMock()
                .counter([0, 0, 0, 1])
                .build()
                .byteArrayRepresentation

        // Create a signature. This part is usually performed by the authenticator

        // ATTENTION: It is very important that we encode `TestClientDataJSON` only once!!! Subsequent calls to
        // `jsonBytes` will result in different json (and thus the signature verification will fail)
        // This has already cost me hours of troubleshooting twice
        let clientData = TestClientDataJSON(type: "webauthn.get").jsonBytes
        let clientDataHash = SHA256.hash(data: clientData)
        let signatureBase = Data(authenticatorData) + clientDataHash
        let signature = try keyConfiguration.signer.sign(data: signatureBase)

        let verifiedAuthentication = try finishAuthentication(
            credentialID: credentialID,
            clientDataJSON: clientData,
            authenticatorData: authenticatorData,
            signature: [UInt8](signature),
            credentialPublicKey: keyConfiguration.credentialPublicKey,
            credentialCurrentSignCount: oldSignCount
        )

        #expect(verifiedAuthentication.credentialID == credentialID.base64URLEncodedString())
        #expect(verifiedAuthentication.newSignCount == oldSignCount + 1)
    }

    /// Using the default parameters `finishAuthentication` should succeed.
    private func finishAuthentication(
        credentialID: [UInt8] = TestConstants.mockCredentialID,
        clientDataJSON: [UInt8] = TestClientDataJSON(type: "webauthn.get").jsonBytes,
        authenticatorData: [UInt8] = TestAuthDataBuilder().validAuthenticationMock().build().byteArrayRepresentation,
        signature: [UInt8],
        userHandle: [UInt8]? = "36323638424436452d303831452d344331312d413743332d334444304146333345433134".hexadecimal!,
        attestationObject: [UInt8]? = nil,
        authenticatorAttachment: AuthenticatorAttachment? = .platform,
        type: CredentialType = .publicKey,
        expectedChallenge: [UInt8] = TestConstants.mockChallenge,
        credentialPublicKey: [UInt8],
        credentialCurrentSignCount: UInt32 = 0,
        requireUserVerification: Bool = false
    ) throws -> VerifiedAuthentication {
        try webAuthnManager.finishAuthentication(
            credential: AuthenticationCredential(
                id: credentialID.base64URLEncodedString(),
                rawID: credentialID,
                response: AuthenticatorAssertionResponse(
                    clientDataJSON: clientDataJSON,
                    authenticatorData: authenticatorData,
                    signature: signature,
                    userHandle: userHandle,
                    attestationObject: attestationObject
                ),
                authenticatorAttachment: authenticatorAttachment,
                type: type
            ),
            expectedChallenge: expectedChallenge,
            credentialPublicKey: credentialPublicKey,
            credentialCurrentSignCount: credentialCurrentSignCount,
            requireUserVerification: requireUserVerification
        )
    }
}
