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
    let relyingPartyID = "example.com"
    let relyingPartyOrigin = "https://example.com"

    override func setUp() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: relyingPartyID,
            relyingPartyName: relyingPartyDisplayName,
            relyingPartyOrigin: relyingPartyOrigin
        )
        webAuthnManager = .init(configuration: configuration, challengeGenerator: .mock(generate: challenge))
    }

    // MARK: - beginRegistration()

    func testBeginRegistrationReturns() throws {
        let user = PublicKeyCredentialUserEntity.mock
        let publicKeyCredentialParameter = PublicKeyCredentialParameters(type: .publicKey, alg: .algES256)
        let options = webAuthnManager.beginRegistration(
            user: user,
            publicKeyCredentialParameters: [publicKeyCredentialParameter]
        )

        XCTAssertEqual(options.challenge, challenge)
        XCTAssertEqual(options.relyingParty.id, relyingPartyID)
        XCTAssertEqual(options.relyingParty.name, relyingPartyDisplayName)
        XCTAssertEqual(options.user.id, user.id)
        XCTAssertEqual(options.user.displayName, user.displayName)
        XCTAssertEqual(options.user.name, user.name)
        XCTAssertEqual(options.publicKeyCredentialParameters, [publicKeyCredentialParameter])
    }

    // MARK: - finishRegistration()

    func testFinishRegistrationFailsIfCeremonyTypeDoesNotMatch() async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.type = "webauthn.get"
        try await assertThrowsError(
            await finishRegistration(clientDataJSON: clientDataJSON.jsonBytes),
            expect: CollectedClientData.CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfChallengeDoesNotMatch() async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.challenge = [0, 2, 4].base64URLEncodedString()
        try await assertThrowsError(
            await finishRegistration(
                challenge: [UInt8]("definitely another challenge".utf8),
                clientDataJSON: clientDataJSON.jsonBytes
            ),
            expect: CollectedClientData.CollectedClientDataVerifyError.challengeDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfOriginDoesNotMatch() async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.origin = "https://random-origin.org"
        // `webAuthnManager` is configured with origin = https://example.com
        try await assertThrowsError(
            await finishRegistration(clientDataJSON: clientDataJSON.jsonBytes),
            expect: CollectedClientData.CollectedClientDataVerifyError.originDoesNotMatch
        )
    }

    func testFinishRegistrationFailsWithInvalidCredentialCreationType() async throws {
        try await assertThrowsError(
            await finishRegistration(type: "foo"),
            expect: WebAuthnError.invalidCredentialCreationType
        )
    }

    func testFinishRegistrationFailsIfClientDataJSONDecodingFails() async throws {
        try await assertThrowsError(await finishRegistration(clientDataJSON: [0])) { (_: DecodingError) in
            return
        }
    }

    func testFinishRegistrationFailsIfAttestationObjectIsNotBase64() async throws {
        try await assertThrowsError(
            await finishRegistration(attestationObject: []),
            expect: WebAuthnError.invalidAttestationObject
        )
    }

    func testFinishRegistrationFailsIfAuthDataIsInvalid() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .invalidAuthData()
                    .build()
                    .cborEncoded
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
                    .build()
                    .cborEncoded
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
                    .build()
                    .cborEncoded
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
                    .build()
                    .cborEncoded
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
                    .build()
                    .cborEncoded
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
                    .build()
                    .cborEncoded
            ),
            expect: WebAuthnError.attestedCredentialFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfExtensionDataFlagIsSetButThereIsNoExtensionData() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().noExtensionData().flags(0b11000001))
                    .build()
                    .cborEncoded
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
                    .build()
                    .cborEncoded
            ),
            expect: WebAuthnError.credentialIDTooShort
        )
    }

    func testFinishRegistrationFailsIfRelyingPartyIDHashDoesNotMatch() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().relyingPartyIDHash(fromRelyingPartyID: "invalid-id.com"))
                    .build()
                    .cborEncoded
            ),
            expect: WebAuthnError.relyingPartyIDHashDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfUserPresentFlagIsNotSet() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().flags(0b11000000))
                    .build()
                    .cborEncoded
            ),
            expect: WebAuthnError.userPresentFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfUserVerificationFlagIsNotSetButRequired() async throws {
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().flags(0b11000001))
                    .build()
                    .cborEncoded,
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
                    .build()
                    .cborEncoded,
                requireUserVerification: true
            ),
            expect: WebAuthnError.attestationStatementMustBeEmpty
        )
    }

    func testFinishRegistrationFailsIfRawIDIsTooLong() async throws {
        try await assertThrowsError(
            await finishRegistration(rawID: [UInt8](repeating: 0, count: 1024)),
            expect: WebAuthnError.credentialRawIDTooLong
        )
    }
    
    func testFinishAuthenticationFailsIfCredentialIDTooLong() async throws {
        /// This should succeed as it's on the border of being acceptable
        _ = try await finishRegistration(
            attestationObject: TestAttestationObjectBuilder()
                .validMock()
                .authData(
                    TestAuthDataBuilder()
                        .validMock()
                        .attestedCredData(
                            credentialIDLength: [0b000_00011, 0b1111_1111],
                            credentialID: Array(repeating: 0, count: 1023),
                            credentialPublicKey: TestCredentialPublicKeyBuilder().validMock().buildAsByteArray()
                        )
                )
                .build()
                .cborEncoded
        )
        
        /// While this one should throw
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(
                        TestAuthDataBuilder()
                            .validMock()
                            .attestedCredData(
                                credentialIDLength: [0b000_00100, 0b0000_0000],
                                credentialID: Array(repeating: 0, count: 1024),
                                credentialPublicKey: TestCredentialPublicKeyBuilder().validMock().buildAsByteArray()
                            )
                    )
                    .build()
                    .cborEncoded
            ),
            expect: WebAuthnError.credentialIDTooLong
        )
    }

    func testFinishRegistrationSucceeds() async throws {
        let credentialID: [UInt8] = [0, 1, 0, 1, 0, 1]
        let credentialPublicKey: [UInt8] = TestCredentialPublicKeyBuilder().validMock().buildAsByteArray()
        let authData = TestAuthDataBuilder()
            .validMock()
            .attestedCredData(credentialPublicKey: credentialPublicKey)
            .noExtensionData()
        let attestationObject = TestAttestationObjectBuilder()
            .validMock()
            .authData(authData)
            .build()
            .cborEncoded

        let credential = try await finishRegistration(
            rawID: credentialID,
            attestationObject: attestationObject
        )
        XCTAssertNotNil(credential)

        XCTAssertEqual(credential.id, credentialID.base64EncodedString().asString())
        XCTAssertEqual(credential.publicKey, credentialPublicKey)
    }

    func testFinishRegistrationFuzzying() async throws {
        for _ in 1...50 {
            let length = Int.random(in: 1...10_000_000)
            let randomAttestationObject = Array(repeating: UInt8.random(), count: length)
            let shouldBeNil = try? await finishRegistration(attestationObject: randomAttestationObject)
            XCTAssertNil(shouldBeNil)
        }
    }

    private func finishRegistration(
        challenge: [UInt8] = TestConstants.mockChallenge,
        type: CredentialType = .publicKey,
        rawID: [UInt8] = "e0fac9350509f71748d83782ccaf6b4c1462c615c70e255da1344e40887c8fcd".hexadecimal!,
        clientDataJSON: [UInt8] = TestClientDataJSON().jsonBytes,
        attestationObject: [UInt8] = TestAttestationObjectBuilder().validMock().build().cborEncoded,
        requireUserVerification: Bool = false,
        confirmCredentialIDNotRegisteredYet: (String) async throws -> Bool = { _ in true }
    ) async throws -> Credential {
        try await webAuthnManager.finishRegistration(
            challenge: challenge,
            credentialCreationData: RegistrationCredential(
                id: rawID.base64URLEncodedString(),
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
