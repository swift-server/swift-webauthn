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

// swiftlint:disable:next type_body_length
final class WebAuthnManagerRegistrationTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!

    let challenge: [UInt8] = [1, 0, 1]
    let relyingPartyDisplayName = "Testy test"
    let relyingPartyID = "webauthn.io"
    let relyingPartyOrigin = "https://example.com"

    override func setUp() {
        let config = WebAuthnConfig(
            relyingPartyDisplayName: relyingPartyDisplayName,
            relyingPartyID: relyingPartyID,
            relyingPartyOrigin: relyingPartyOrigin
        )
        webAuthnManager = .init(config: config, challengeGenerator: .mock(generate: challenge))
    }

    // MARK: - beginRegistration()

    func testBeginRegistrationReturns() throws {
        let user = MockUser()
        let publicKeyCredentialParameter = PublicKeyCredentialParameters(type: "public-key", alg: .algES256)
        let options = try webAuthnManager.beginRegistration(
            user: user,
            publicKeyCredentialParameters: [publicKeyCredentialParameter]
        )

        XCTAssertEqual(options.challenge, challenge.base64EncodedString())
        XCTAssertEqual(options.rp.id, relyingPartyID)
        XCTAssertEqual(options.rp.name, relyingPartyDisplayName)
        XCTAssertEqual(options.user.id, user.userID.toBase64().asString())
        XCTAssertEqual(options.user.displayName, user.displayName)
        XCTAssertEqual(options.user.name, user.name)
        XCTAssertEqual(options.pubKeyCredParams, [publicKeyCredentialParameter])
    }

    // MARK: - finishRegistration()

    func testFinishRegistrationFailsIfCeremonyTypeDoesNotMatch() async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.type = "webauthn.get"
        try await assertThrowsError(
            await finishRegistration(clientDataJSON: clientDataJSON.base64URLEncoded),
            expect: CollectedClientData.CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfChallengeDoesNotMatch() async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.challenge = "some random challenge"
        try await assertThrowsError(
            await finishRegistration(
                challenge: "definitely another challenge",
                clientDataJSON: clientDataJSON.base64URLEncoded
            ),
            expect: CollectedClientData.CollectedClientDataVerifyError.challengeDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfOriginDoesNotMatch() async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.origin = "https://random-origin.org"
        // `webAuthnManager` is configured with origin = https://example.com
        try await assertThrowsError(
            await finishRegistration(
                clientDataJSON: clientDataJSON.base64URLEncoded
            ),
            expect: CollectedClientData.CollectedClientDataVerifyError.originDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfClientDataJSONIsInvalid() async throws {
        try await assertThrowsError(
            await finishRegistration(clientDataJSON: "%"),
            expect: WebAuthnError.invalidClientDataJSON
        )
    }

    func testFinishRegistrationFailsWithInvalidRawID() async throws {
        try await assertThrowsError(await finishRegistration(rawID: "%"), expect: WebAuthnError.invalidRawID)
    }

    func testFinishRegistrationFailsWithInvalidCredentialCreationType() async throws {
        try await assertThrowsError(
            await finishRegistration(type: "foo"),
            expect: WebAuthnError.invalidCredentialCreationType
        )
    }

    func testFinishRegistrationFailsWithInvalidClientDataJSON() async throws {
        try await assertThrowsError(
            await finishRegistration(clientDataJSON: "%%%"),
            expect: WebAuthnError.invalidClientDataJSON
        )
    }

    func testFinishRegistrationFailsIfClientDataJSONDecodingFails() async throws {
        try await assertThrowsError(await finishRegistration(clientDataJSON: "abc")) { (_: DecodingError) in
            return
        }
    }

    func testFinishRegistrationFailsIfAttestationObjectIsNotBase64() async throws {
        try await assertThrowsError(
            await finishRegistration(attestationObject: "%%%"),
            expect: WebAuthnError.invalidAttestationObject
        )
    }

    func testFinishRegistrationFailsIfAuthDataIsInvalid() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .invalidAuthData()
                    .buildBase64URLEncoded()
            ),
            expect: WebAuthnError.invalidAuthData
        )
    }

    func testFinishRegistrationFailsIfFmtIsInvalid() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .invalidFmt()
                    .buildBase64URLEncoded()
            ),
            expect: WebAuthnError.invalidFmt
        )
    }

    func testFinishRegistrationFailsIfAttStmtIsMissing() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .missingAttStmt()
                    .buildBase64URLEncoded()
            ),
            expect: WebAuthnError.missingAttStmt
        )
    }

    func testFinishRegistrationFailsIfAuthDataIsTooShort() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .zeroAuthData(byteCount: 36)
                    .buildBase64URLEncoded()
            ),
            expect: WebAuthnError.authDataTooShort
        )
    }

    func testFinishRegistrationFailsIfAttestedCredentialDataFlagIsSetButThereIsNoCredentialData() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(
                        TestAuthDataBuilder()
                            .validMock()
                            .flags(0b01000001)
                            .noAttestedCredentialData()
                            .noExtensionData()
                    )
                    .buildBase64URLEncoded()
            ),
            expect: WebAuthnError.attestedCredentialDataMissing
        )
    }

    func testFinishRegistrationFailsIfAttestedCredentialDataFlagIsNotSetButThereIsCredentialData() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(
                        TestAuthDataBuilder()
                            .validMock()
                            .flags(0b00000001)
                            .attestedCredData(credentialPublicKey: [])
                    )
                    .buildBase64URLEncoded()
            ),
            expect: WebAuthnError.attestedCredentialFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfExtensionDataFlagIsSetButThereIsNoExtensionData() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().flags(0b11000001).noExtensionData())
                    .buildBase64URLEncoded()
            ),
            expect: WebAuthnError.extensionDataMissing
        )
    }

    func testFinishRegistrationFailsIfCredentialIdIsTooShort() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(
                        TestAuthDataBuilder()
                            .validMock()
                            .attestedCredData(
                                credentialIDLength: [0b00000000, 0b00000010], // we expect length = 2
                                credentialID: [255], // but only get length = 1
                                credentialPublicKey: []
                            )
                            .noExtensionData()
                    )
                    .buildBase64URLEncoded()
            ),
            expect: WebAuthnError.credentialIDTooShort
        )
    }

    func testFinishRegistrationFailsIfRelyingPartyIDHashDoesNotMatch() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().rpIDHash(fromRpID: "invalid-id.com"))
                    .buildBase64URLEncoded()
            ),
            expect: WebAuthnError.relyingPartyIDHashDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfUserPresentFlagIsNotSet() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().flags(0b01000000))
                    .buildBase64URLEncoded()
            ),
            expect: WebAuthnError.userPresentFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfUserVerificationFlagIsNotSetButRequired() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().flags(0b01000001))
                    .buildBase64URLEncoded(),
                requireUserVerification: true
            ),
            expect: WebAuthnError.userVerificationRequiredButFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfAttFmtIsNoneButAttStmtIsIncluded() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .fmt("none")
                    .attStmt(.double(123))
                    .buildBase64URLEncoded(),
                requireUserVerification: true
            ),
            expect: WebAuthnError.attestationStatementMustBeEmpty
        )
    }

    func testFinishRegistrationFailsIfRawIDIsTooLong() async throws {
        try await assertThrowsError(
            await finishRegistration(rawID: [UInt8](repeating: 0, count: 1024).base64EncodedString().urlEncoded),
            expect: WebAuthnError.credentialRawIDTooLong
        )
    }

    func testFinishRegistrationSucceeds() async throws {
        let credentialID = [0, 1, 0, 1, 0, 1].base64EncodedString()
        let credentialPublicKey: [UInt8] = TestCredentialPublicKeyBuilder().validMock().buildAsByteArray()
        let authData = TestAuthDataBuilder()
            .validMock()
            .attestedCredData(credentialPublicKey: credentialPublicKey)
            .noExtensionData()
        let attestationObject = TestAttestationObjectBuilder()
            .validMock()
            .authData(authData)
            .buildBase64URLEncoded()
        let credential = try await finishRegistration(id: credentialID, attestationObject: attestationObject)
        XCTAssertNotNil(credential)

        XCTAssertEqual(credential.id, credentialID.asString())
        XCTAssertEqual(credential.publicKey, credentialPublicKey)
    }

    // Swift CBOR library currently crashes when running this test. WE NEED TO FIX THIS
    // TODO: Fix this test
    // func testFinishRegistrationFuzzying() async throws {
    //     for _ in 1...50 {
    //         let length = Int.random(in: 1...10_000_000)
    //         let randomAttestationObject: URLEncodedBase64 = Data(
    //             [UInt8](repeating: UInt8.random(), count: length)
    //         ).base64URLEncodedString()
    //         let shouldBeNil = try? await finishRegistration(attestationObject: randomAttestationObject)
    //         XCTAssertNil(shouldBeNil)
    //     }
    // }

    private func finishRegistration(
        challenge: EncodedBase64 = "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg", // "randomStringFromServer"
        id: EncodedBase64 = "4PrJNQUJ9xdI2DeCzK9rTBRixhXHDiVdoTROQIh8j80",
        type: String = "public-key",
        rawID: URLEncodedBase64 = "4PrJNQUJ9xdI2DeCzK9rTBRixhXHDiVdoTROQIh8j80",
        clientDataJSON: URLEncodedBase64 = TestClientDataJSON().base64URLEncoded,
        attestationObject: URLEncodedBase64 = TestAttestationObjectBuilder().validMock().buildBase64URLEncoded(),
        requireUserVerification: Bool = false,
        confirmCredentialIDNotRegisteredYet: (String) async throws -> Bool = { _ in true }
    ) async throws -> Credential {
        try await webAuthnManager.finishRegistration(
            challenge: challenge,
            credentialCreationData: RegistrationCredential(
                id: id.asString(),
                type: type,
                rawID: rawID,
                attestationResponse: AuthenticatorAttestationResponse(
                    clientDataJSON: clientDataJSON,
                    attestationObject: attestationObject
                )
            ),
            requireUserVerification: requireUserVerification,
            confirmCredentialIDNotRegisteredYet: confirmCredentialIDNotRegisteredYet
        )
    }
}
