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
        let options = try webAuthnManager.beginAuthentication(
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

    @Test
    func finishAuthenticationFailsIfCredentialTypeIsInvalid() throws {
        try assertThrowsError(
            finishAuthentication(type: "invalid"),
            expect: WebAuthnError.invalidAssertionCredentialType
        )
    }

    @Test
    func finishAuthenticationFailsIfClientDataJSONDecodingFails() throws {
        try assertThrowsError(finishAuthentication(clientDataJSON: [0])) { (_: DecodingError) in
            return
        }
    }
    
    @Test
    func finishAuthenticationFailsIfCeremonyTypeDoesNotMatch() throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.type = "webauthn.create"
        try assertThrowsError(
            finishAuthentication(clientDataJSON: clientDataJSON.jsonBytes),
            expect: CollectedClientData.CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch
        )
    }

    @Test
    func finishAuthenticationFailsIfRelyingPartyIDHashDoesNotMatch() throws {
        try assertThrowsError(
            finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .relyingPartyIDHash(fromRelyingPartyID: "wrong-id.org")
                    .build()
                    .byteArrayRepresentation
            ),
            expect: WebAuthnError.relyingPartyIDHashDoesNotMatch
        )
    }

    @Test
    func finishAuthenticationFailsIfUserPresentFlagIsNotSet() throws {
        try assertThrowsError(
            finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .flags(0b10000000)
                    .build()
                    .byteArrayRepresentation
            ),
            expect: WebAuthnError.userPresentFlagNotSet
        )
    }

    @Test
    func finishAuthenticationFailsIfUserIsNotVerified() throws {
        try assertThrowsError(
            finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .flags(0b10000001)
                    .build()
                    .byteArrayRepresentation,
                requireUserVerification: true
            ),
            expect: WebAuthnError.userVerifiedFlagNotSet
        )
    }

    @Test
    func finishAuthenticationFailsIfCredentialCounterIsNotUpToDate() throws {
        try assertThrowsError(
            finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .counter([0, 0, 0, 1]) // signCount = 1
                    .build()
                    .byteArrayRepresentation,
                credentialCurrentSignCount: 2
            ),
            expect: WebAuthnError.potentialReplayAttack
        )
    }

    @Test
    func finishAuthenticationSucceeds() throws {
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
        let signature = try TestECCKeyPair.signature(data: signatureBase).derRepresentation

        let verifiedAuthentication = try finishAuthentication(
            credentialID: credentialID,
            clientDataJSON: clientData,
            authenticatorData: authenticatorData,
            signature: [UInt8](signature),
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
        signature: [UInt8] = TestECCKeyPair.signature,
        userHandle: [UInt8]? = "36323638424436452d303831452d344331312d413743332d334444304146333345433134".hexadecimal!,
        attestationObject: [UInt8]? = nil,
        authenticatorAttachment: AuthenticatorAttachment? = .platform,
        type: CredentialType = .publicKey,
        expectedChallenge: [UInt8] = TestConstants.mockChallenge,
        credentialPublicKey: [UInt8] = TestCredentialPublicKeyBuilder().validMock().buildAsByteArray(),
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
