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
import SwiftCBOR
import Crypto

// swiftlint:disable line_length

extension WebAuthnManagerTests {
    func testBeginAuthentication() async throws {
        let allowCredentials: [PublicKeyCredentialDescriptor] = [.init(type: "public-key", id: [1, 0, 2, 30])]
        let options = try webAuthnManager.beginAuthentication(
            timeout: timeout,
            allowCredentials: allowCredentials,
            userVerification: .preferred
        )

        XCTAssertEqual(options.challenge, challenge.base64EncodedString())
        XCTAssertEqual(options.timeout, timeout)
        XCTAssertEqual(options.rpId, relyingPartyID)
        XCTAssertEqual(options.allowCredentials, allowCredentials)
        XCTAssertEqual(options.userVerification, .preferred)
    }

    func testFinishAuthenticationFailsIfCredentialTypeIsInvalid() throws {
        try assertThrowsError(
            finishAuthentication(type: "invalid"),
            expect: WebAuthnError.invalidAssertionCredentialType
        )
    }

    func testFinishAuthenticationFailsIfClientDataJSONIsNotBase64() throws {
        try assertThrowsError(
            finishAuthentication(clientDataJSON: "%"),
            expect: WebAuthnError.invalidClientDataJSON
        )
    }

    func testFinishAuthenticationFailsIfClientDataJSONDecodingFails() throws {
        try assertThrowsError(finishAuthentication(clientDataJSON: "abc")) { (_: DecodingError) in
            return
        }
    }

    func testFinishAuthenticationFailsIfAuthenticatorDataIsInvalid() throws {
        try assertThrowsError(
            finishAuthentication(authenticatorData: "%"),
            expect: WebAuthnError.invalidAuthenticatorData
        )
    }

    func testFinishAuthenticationFailsIfCeremonyTypeDoesNotMatch() throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.type = "webauthn.create"
        try assertThrowsError(
            finishAuthentication(clientDataJSON: clientDataJSON.base64URLEncoded),
            expect: CollectedClientData.CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch
        )
    }

    func testFinishAuthenticationFailsIfRelyingPartyIDHashDoesNotMatch() throws {
        try assertThrowsError(
            finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .rpIDHash(fromRpID: "wrong-id.org")
                    .buildAsBase64URLEncoded()
            ),
            expect: WebAuthnError.relyingPartyIDHashDoesNotMatch
        )
    }

    func testFinishAuthenticationFailsIfUserPresentFlagIsNotSet() throws {
        try assertThrowsError(
            finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .flags(0b10000000)
                    .buildAsBase64URLEncoded()
            ),
            expect: WebAuthnError.userPresentFlagNotSet
        )
    }

    func testFinishAuthenticationFailsIfUserIsNotVerified() throws {
        try assertThrowsError(
            finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .flags(0b10000001)
                    .buildAsBase64URLEncoded(),
                requireUserVerification: true
            ),
            expect: WebAuthnError.userVerifiedFlagNotSet
        )
    }

    func testFinishAuthenticationFailsIfCredentialCounterIsNotUpToDate() throws {
        try assertThrowsError(
            finishAuthentication(
                authenticatorData: TestAuthDataBuilder()
                    .validAuthenticationMock()
                    .counter([0, 0, 0, 1]) // signCount = 1
                    .buildAsBase64URLEncoded(),
                credentialCurrentSignCount: 2
            ),
            expect: WebAuthnError.potentialReplayAttack
        )
    }

    func testFinishAuthenticationSucceeds() throws {
        let credentialID = TestConstants.mockCredentialID
        let oldSignCount: UInt32 = 0

        let authenticatorData = TestAuthDataBuilder()
                .validAuthenticationMock()
                .counter([0, 0, 0, 1])
                .buildAsBase64URLEncoded()

        // create a signature. This part is usually performed by the authenticator
        let clientDataHash = SHA256.hash(data: TestClientDataJSON(type: "webauthn.get").jsonData)
        let rawAuthenticatorData = authenticatorData.urlDecoded.decoded!
        let signatureBase = rawAuthenticatorData + clientDataHash
        let signature = try TestECCKeyPair.signature(data: signatureBase).derRepresentation

        let verifiedAuthentication = try finishAuthentication(
            credentialID: credentialID,
            authenticatorData: authenticatorData,
            signature: signature.base64URLEncodedString(),
            credentialCurrentSignCount: oldSignCount
        )

        XCTAssertEqual(verifiedAuthentication.credentialID, credentialID)
        XCTAssertEqual(verifiedAuthentication.newSignCount, oldSignCount + 1)
    }

    /// Using the default parameters `finishAuthentication` should succeed.
    private func finishAuthentication(
        credentialID: URLEncodedBase64 = TestConstants.mockCredentialID,
        clientDataJSON: URLEncodedBase64 = TestClientDataJSON(type: "webauthn.get").base64URLEncoded,
        authenticatorData: URLEncodedBase64 = TestAuthDataBuilder().validAuthenticationMock()
            .buildAsBase64URLEncoded(),
        signature: URLEncodedBase64 = "MEUCIQCs67ijqtM-Ow5UBvIT5afc_4RQZDLbfoXOnFgDUsYymQIgIdSmullkPCYrdES4-HBMkL-dL5FXr9gjqUfsdXvnxp8",
        userHandle: String? = "NjI2OEJENkUtMDgxRS00QzExLUE3QzMtM0REMEFGMzNFQzE0",
        attestationObject: String? = nil,
        authenticatorAttachment: String? = "platform",
        type: String = "public-key",
        expectedChallenge: URLEncodedBase64 = TestConstants.mockChallenge,
        credentialPublicKey: [UInt8] = TestCredentialPublicKeyBuilder().validMock().buildAsByteArray(),
        credentialCurrentSignCount: UInt32 = 0,
        requireUserVerification: Bool = false
    ) throws -> VerifiedAuthentication {
        try webAuthnManager.finishAuthentication(
            credential: AuthenticationCredential(
                id: credentialID,
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
