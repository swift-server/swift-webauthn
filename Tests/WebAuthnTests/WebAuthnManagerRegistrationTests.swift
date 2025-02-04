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
import SwiftCBOR

// swiftlint:disable:next type_body_length
struct WebAuthnManagerRegistrationTests {
    var webAuthnManager: WebAuthnManager!

    let challenge: [UInt8] = [1, 0, 1]
    let relyingPartyDisplayName = "Testy test"
    let relyingPartyID = "example.com"
    let relyingPartyOrigin = "https://example.com"

    init() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: relyingPartyID,
            relyingPartyName: relyingPartyDisplayName,
            relyingPartyOrigin: relyingPartyOrigin
        )
        webAuthnManager = .init(configuration: configuration, challengeGenerator: .mock(generate: challenge))
    }

    // MARK: - beginRegistration()
    @Test
    func beginRegistrationReturns()  {
        let user = PublicKeyCredentialUserEntity.mock
        let publicKeyCredentialParameter = PublicKeyCredentialParameters(type: .publicKey, alg: .algES256)
        let options = webAuthnManager.beginRegistration(
            user: user,
            publicKeyCredentialParameters: [publicKeyCredentialParameter]
        )

        #expect(options.challenge == challenge)
        #expect(options.relyingParty.id == relyingPartyID)
        #expect(options.relyingParty.name == relyingPartyDisplayName)
        #expect(options.user.id == user.id)
        #expect(options.user.displayName == user.displayName)
        #expect(options.user.name == user.name)
        #expect(options.publicKeyCredentialParameters == [publicKeyCredentialParameter])
    }

    // MARK: - finishRegistration()
    
    @Test
    func finishRegistrationFailsIfCeremonyTypeDoesNotMatch() async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.type = "webauthn.get"
        await #expect(throws: CollectedClientData.CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch) {
            try await finishRegistration(clientDataJSON: clientDataJSON.jsonBytes)
        }
    }
    
    @Test
    func finishRegistrationFailsIfChallengeDoesNotMatch() async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.challenge = [0, 2, 4].base64URLEncodedString()
        await #expect(throws: CollectedClientData.CollectedClientDataVerifyError.challengeDoesNotMatch) {
            try await finishRegistration(
                challenge: [UInt8]("definitely another challenge".utf8),
                clientDataJSON: clientDataJSON.jsonBytes
            )
        }
    }
    
    @Test
    func finishRegistrationFailsIfOriginDoesNotMatch() async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.origin = "https://random-origin.org"
        // `webAuthnManager` is configured with origin = https://example.com
        await #expect(throws: CollectedClientData.CollectedClientDataVerifyError.originDoesNotMatch) {
            try await finishRegistration(clientDataJSON: clientDataJSON.jsonBytes)
        }
    }
    
    @Test
    func finishRegistrationFailsWithInvalidCredentialCreationType() async throws {
        await #expect(throws: WebAuthnError.invalidCredentialCreationType) {
            try await finishRegistration(type: "foo")
        }
    }

    @Test
    func finishRegistrationFailsIfClientDataJSONDecodingFails() async throws {
        await #expect(throws: DecodingError.self) {
            try await finishRegistration(clientDataJSON: [0])
        }
    }
    
    @Test
    func finishRegistrationFailsIfAttestationObjectIsNotBase64() async throws {
        await #expect(throws: WebAuthnError.invalidAttestationObject) {
            try await finishRegistration(attestationObject: [])
        }
    }

    @Test
    func finishRegistrationFailsIfAuthDataIsInvalid() async throws {
        await #expect(throws: WebAuthnError.invalidAuthData) {
            try await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .invalidAuthData()
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test
    func finishRegistrationFailsIfFmtIsInvalid() async throws {
        await #expect(throws: WebAuthnError.invalidFmt) {
            try await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .invalidFmt()
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test
    func finishRegistrationFailsIfAttStmtIsMissing() async throws {
        await #expect(throws: WebAuthnError.missingAttStmt) {
            try await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .missingAttStmt()
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test
    func finishRegistrationFailsIfAuthDataIsTooShort() async throws {
        await #expect(throws: WebAuthnError.authDataTooShort) {
            try await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .zeroAuthData(byteCount: 36)
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test
    func finishRegistrationFailsIfAttestedCredentialDataFlagIsSetButThereIsNoCredentialData() async throws {
        await #expect(throws: WebAuthnError.attestedCredentialDataMissing) {
            try await finishRegistration(
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
            )
        }
    }

    @Test
    func finishRegistrationFailsIfAttestedCredentialDataFlagIsNotSetButThereIsCredentialData() async throws {
        await #expect(throws: WebAuthnError.attestedCredentialFlagNotSet) {
            try await finishRegistration(
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
            )
        }
    }

    @Test
    func finishRegistrationFailsIfExtensionDataFlagIsSetButThereIsNoExtensionData() async throws {
        await #expect(throws: WebAuthnError.extensionDataMissing) {
            try await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().noExtensionData().flags(0b11000001))
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test
    func finishRegistrationFailsIfCredentialIdIsTooShort() async throws {
        await #expect(throws: WebAuthnError.credentialIDTooShort) {
            try await finishRegistration(
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
            )
        }
    }

    @Test
    func finishRegistrationFailsIfRelyingPartyIDHashDoesNotMatch() async throws {
        await #expect(throws: WebAuthnError.relyingPartyIDHashDoesNotMatch) {
            try await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().relyingPartyIDHash(fromRelyingPartyID: "invalid-id.com"))
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test
    func finishRegistrationFailsIfUserPresentFlagIsNotSet() async throws {
        await #expect(throws: WebAuthnError.userPresentFlagNotSet) {
            try await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().flags(0b11000000))
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test
    func finishRegistrationFailsIfUserVerificationFlagIsNotSetButRequired() async throws {
        await #expect(throws: WebAuthnError.userVerificationRequiredButFlagNotSet) {
            try await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .authData(TestAuthDataBuilder().validMock().flags(0b11000001))
                    .build()
                    .cborEncoded,
                requireUserVerification: true
            )
        }
    }

    @Test
    func finishRegistrationFailsIfAttFmtIsNoneButAttStmtIsIncluded() async throws {
        await #expect(throws: WebAuthnError.attestationStatementMustBeEmpty) {
            try await finishRegistration(
                attestationObject: TestAttestationObjectBuilder()
                    .validMock()
                    .fmt("none")
                    .attStmt(.double(123))
                    .build()
                    .cborEncoded,
                requireUserVerification: true
            )
        }
    }

    @Test
    func finishRegistrationFailsIfRawIDIsTooLong() async throws {
        await #expect(throws: WebAuthnError.credentialRawIDTooLong) {
            try await finishRegistration(rawID: [UInt8](repeating: 0, count: 1024))
        }
    }
    
    @Test
    func finishAuthenticationFailsIfCredentialIDTooLong() async throws {
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
        await #expect(throws: WebAuthnError.credentialIDTooLong) {
            try await finishRegistration(
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
            )
        }
    }

    @Test
    func finishRegistrationSucceeds() async throws {
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
        #expect(credential != nil)

        #expect(credential.id == credentialID.base64EncodedString().asString())
        #expect(credential.publicKey == credentialPublicKey)
    }
    
    @Test
    func finishRegistrationFuzzying() async throws {
        for _ in 1...50 {
            let length = Int.random(in: 1...10_000_000)
            let randomAttestationObject = Array(repeating: UInt8.random(), count: length)
            let shouldBeNil = try? await finishRegistration(attestationObject: randomAttestationObject)
            #expect(shouldBeNil == nil)
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
