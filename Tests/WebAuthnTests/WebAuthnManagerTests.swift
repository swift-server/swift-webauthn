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

// swiftlint:disable line_length

final class WebAuthnManagerTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!

    let challenge: [UInt8] = [1, 0, 1]
    let relyingPartyDisplayName = "Testy test"
    let relyingPartyID = "example.com"
    let relyingPartyOrigin = "https://example.com"
    let timeout: TimeInterval = 6000

    override func setUp() {
        let config = WebAuthnConfig(
            relyingPartyDisplayName: relyingPartyDisplayName,
            relyingPartyID: relyingPartyID,
            relyingPartyOrigin: relyingPartyOrigin,
            timeout: timeout
        )
        webAuthnManager = .init(config: config, challengeGenerator: .mock(generate: challenge))
    }

    func testBeginRegistrationReturns() throws {
        let user = MockUser()
        let publicKeyCredentialParameter = PublicKeyCredentialParameters(type: "public-key", algorithm: .algPS384)
        let options = try webAuthnManager.beginRegistration(
            user: user,
            publicKeyCredentialParameters: [publicKeyCredentialParameter]
        )

        XCTAssertEqual(options.challenge, challenge.base64EncodedString())
        XCTAssertEqual(options.relyingParty.id, relyingPartyID)
        XCTAssertEqual(options.relyingParty.name, relyingPartyDisplayName)
        XCTAssertEqual(options.timeout, timeout)
        XCTAssertEqual(options.user.id, user.userID.toBase64())
        XCTAssertEqual(options.user.displayName, user.displayName)
        XCTAssertEqual(options.user.name, user.name)
        XCTAssertEqual(options.publicKeyCredentialParameters, [publicKeyCredentialParameter])
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
        try await assertThrowsError(await finishRegistration(clientDataJSON: "abc")) { (error: DecodingError) in
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
        let hexAttestationObjectWithInvalidAuthData: URLEncodedBase64 = "A363666D74667061636B65646761747453746D74A263616C67266373696758473045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C68617574684461746101"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectWithInvalidAuthData),
            expect: WebAuthnError.invalidAuthData
        )
    }

    func testFinishRegistrationFailsIfFmtIsInvalid() async throws {
        let hexAttestationObjectWithInvalidFmt: URLEncodedBase64 = "o2NmbXQBZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIDo-5W3Kur7A7y9Lfw7ijhExfCz3_5coMEQNY_y6p-JrpQECAyYgASFYIJr_yLoYbYWgcf7aQcd7pcjUj-3o8biafWQH28WijQSvIlggPI2KqqRQ26KKuFaJ0yH7nouCBrzHu8qRONW-CPa9VDM"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectWithInvalidFmt),
            expect: WebAuthnError.invalidFmt
        )
    }

    func testFinishRegistrationFailsIfAttStmtIsMissing() async throws {
        let hexAttestationObjectWithMissingAttStmt: URLEncodedBase64 = "omNmbXRmcGFja2VkaGF1dGhEYXRhWKRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAAArc4AAjW8xgpkiwsl8fBVAwAgOj7lbcq6vsDvL0t_DuKOETF8LPf_lygwRA1j_Lqn4mulAQIDJiABIVggmv_IuhhthaBx_tpBx3ulyNSP7ejxuJp9ZAfbxaKNBK8iWCA8jYqqpFDbooq4VonTIfuei4IGvMe7ypE41b4I9r1UMw"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectWithMissingAttStmt),
            expect: WebAuthnError.missingAttStmt
        )
    }

    func testFinishRegistrationFailsIfAuthDataIsTooShort() async throws {
        let hexAttestationObjectInvalidAuthData: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YUNJlg0"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectInvalidAuthData),
            expect: WebAuthnError.authDataTooShort
        )
    }

    func testFinishRegistrationFailsIfAttestedCredentialDataFlagIsSetButThereIsNotCredentialData() async throws {
        let hexAttestationObjectMissingCredentialData: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVglVkdobFZHaGxWR2hsVkdobFZHaGxWR2hsaGxWR2hsaGxAAAAAAA"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectMissingCredentialData),
            expect: WebAuthnError.attestedCredentialDataMissing
        )
    }

    func testFinishRegistrationFailsIfAttestedCredentialDataFlagIsNotSetButThereIsCredentialData() async throws {
        let hexAttestationObjectWithCredentialData: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVgmVkdobFZHaGxWR2hsVkdobFZHaGxWR2hsaGxWR2hsaGwAAAAAAAA"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectWithCredentialData),
            expect: WebAuthnError.attestedCredentialFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfExtensionDataFlagIsSetButThereIsNoExtensionData() async throws {
        let hexAttestationObjectMissingExtensionData: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVglVkdobFZHaGxWR2hsVkdobFZHaGxWR2hsaGxWR2hsaGyAAAAAAA"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectMissingExtensionData),
            expect: WebAuthnError.extensionDataMissing
        )
    }

    func testFinishRegistrationFailsIfCredentialIdIsTooShort() async throws {
        let hexAttestationShortCredentialID: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVg4VkdobFZHaGxWR2hsVkdobFZHaGxWR2hsaGxWR2hsaGxAAAAAAFZHaGxWR2hsVkdobFZHaGwAAio"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationShortCredentialID),
            expect: WebAuthnError.credentialIDTooShort
        )
    }

    func testFinishRegistrationFailsIfCeremonyTypeDoesNotMatch() async throws {
        let clientDataJSONWrongCeremonyType: URLEncodedBase64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"
        try await assertThrowsError(
            await finishRegistration(clientDataJSON: clientDataJSONWrongCeremonyType),
            expect: CollectedClientData.CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfChallengeDoesNotMatch() async throws {
        let clientDataJSONWrongChallenge: URLEncodedBase64 = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"
        try await assertThrowsError(
            await finishRegistration(
                challenge: "definitelyAnotherChallenge",
                clientDataJSON: clientDataJSONWrongChallenge
            ),
            expect: CollectedClientData.CollectedClientDataVerifyError.challengeDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfOriginDoesNotMatch() async throws {
        // origin = http://johndoe.com
        let clientDataJSONWrongOrigin: URLEncodedBase64 = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2pvaG5kb2UuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"

        // `webAuthnManager` is configured with origin = https://example.com
        try await assertThrowsError(
            await finishRegistration(
                challenge: "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg",
                clientDataJSON: clientDataJSONWrongOrigin
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

    func testFinishRegistrationFailsIfRelyingPartyIDHashDoesNotMatch() async throws {
        let hexAttestationObjectMismatchingRpId: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVg4SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAATo"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectMismatchingRpId),
            expect: WebAuthnError.relyingPartyIDHashDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfUserPresentFlagIsNotSet() async throws {
        let hexAttestationObjectMismatchingRpId: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVg4o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdAAAAAAK3OAAI1vMYKZIsLJfHwVQMAATo"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectMismatchingRpId),
            expect: WebAuthnError.userPresentFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfUserVerificationFlagIsNotSetButRequired() async throws {
        let hexAttestationObjectUVFlagNotSet: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVg4o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdBAAAAAK3OAAI1vMYKZIsLJfHwVQMAATo"
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: hexAttestationObjectUVFlagNotSet,
                requireUserVerification: true
            ),
            expect: WebAuthnError.userVerificationRequiredButFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfAttFmtIsNoneButAttStmtIsIncluded() async throws {
        let hexAttestationObjectAttStmtNoneWithAttStmt: URLEncodedBase64 = "o2NmbXRkbm9uZWdhdHRTdG10oWVoZWxsb2V3b3JsZGhhdXRoRGF0YVg5o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdBAAAAAKN5pvbur7mlXjeMEYA04nUAAQAA"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectAttStmtNoneWithAttStmt),
            expect: WebAuthnError.attestationStatementMustBeEmpty
        )
    }

    func testFinishRegistrationFailsIfRawIDIsTooLong() async throws {
        try await assertThrowsError(
            await finishRegistration(rawID: [UInt8](repeating: 0, count: 1024).base64EncodedString()),
            expect: WebAuthnError.credentialRawIDTooLong
        )
    }

    private func finishRegistration(
        challenge: EncodedBase64 = "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg",
        id: EncodedBase64 = "4PrJNQUJ9xdI2DeCzK9rTBRixhXHDiVdoTROQIh8j80",
        type: String = "public-key",
        rawID: EncodedBase64 = "4PrJNQUJ9xdI2DeCzK9rTBRixhXHDiVdoTROQIh8j80",
        clientDataJSON: String = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9",
        attestationObject: String = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVg5o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdBAAAAAKN5pvbur7mlXjeMEYA04nUAAQAA",
        requireUserVerification: Bool = false,
        confirmCredentialIDNotRegisteredYet: (String) async throws -> Bool = { _ in true }
    ) async throws -> Credential {
        try await webAuthnManager.finishRegistration(
            challenge: challenge,
            credentialCreationData: RegistrationCredential(
                id: id,
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
