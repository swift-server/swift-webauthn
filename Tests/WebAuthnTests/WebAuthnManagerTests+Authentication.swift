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
        // {
        //   "type":"webauthn.create",
        //   "challenge":"jZGE93wyfZbd0OF5LlRumoTCPLlU7XQaYMglJWPPspWSpaMf-sqTXOIV28AW8iZV95uiG-8BH6zddICo9ZGrWA",
        //   "origin":"https://webauthn.io",
        //   "crossOrigin":false
        // }
        try assertThrowsError(
            finishAuthentication(clientDataJSON: "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoialpHRTkzd3lmWmJkME9GNUxsUnVtb1RDUExsVTdYUWFZTWdsSldQUHNwV1NwYU1mLXNxVFhPSVYyOEFXOGlaVjk1dWlHLThCSDZ6ZGRJQ285WkdyV0EiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"),
            expect: CollectedClientData.CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch
        )
    }

    func testFinishAuthenticationFailsIfRelyingPartyIDHashDoesNotMatch() throws {
        try assertThrowsError(
            finishAuthentication(authenticatorData: "SJYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA"),
            expect: WebAuthnError.relyingPartyIDHashDoesNotMatch
        )
    }

    func testFinishAuthenticationFailsIfUserPresentFlagIsNotSet() throws {
        try assertThrowsError(
            finishAuthentication(authenticatorData: "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAEAAAAAA"),
            expect: WebAuthnError.userPresentFlagNotSet
        )
    }

    func testFinishAuthenticationFailsIfUserIsNotVerified() throws {
        try assertThrowsError(
            finishAuthentication(
                authenticatorData: "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvABAAAAAA",
                requireUserVerification: true
            ),
            expect: WebAuthnError.userVerifiedFlagNotSet
        )
    }

    func testFinishAuthenticationFailsIfCredentialCounterIsNotUpToDate() throws {
        try assertThrowsError(
            finishAuthentication(
                authenticatorData: "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAAAQ", // signCount = 1
                credentialCurrentSignCount: 2
            ),
            expect: WebAuthnError.potentialReplayAttack
        )
    }

    private func finishAuthentication(
        credentialID: String = "t17cFo-duGmNFikXovKNdxJeKt1opiOhNbGB0SVP9Jc",
        clientDataJSON: URLEncodedBase64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoic29tZUNoYWxsZW5nZSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
        authenticatorData: URLEncodedBase64 = "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAAAA",
        signature: String = "MEQCIERtRvAoEUoIaJSK3LjjdPc8Rti0rlc7ce98paobF9tQAiB9KrKDwRFA7Rsfnhaik1wxJzlO-yYPynEy91WL9tfaAg",
        userHandle: String? = "NjI2OEJENkUtMDgxRS00QzExLUE3QzMtM0REMEFGMzNFQzE0",
        attestationObject: String? = nil,
        authenticatorAttachment: String? = "platform",
        type: String = "public-key",
        expectedChallenge: URLEncodedBase64 = "someChallenge",
        credentialPublicKey: [UInt8] = [UInt8]("pQECAyYgASFYIHHav63TRyKma7L7duPysRTSZ0u_l_ezg_ALplDTEfBmIlggxsiNa6gSWfFLFDOnhMKTTYurKp66FMpWAt2ZFbhTEPs".base64URLDecodedData!),
        credentialCurrentSignCount: Int = 0,
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
