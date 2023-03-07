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
// swiftlint:disable identifier_name

final class WebAuthnManagerTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!

    let challenge: [UInt8] = [1, 0, 1]
    let relyingPartyDisplayName = "Testy test"
    let relyingPartyID = "webauthn.io"
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
        let publicKeyCredentialParameter = PublicKeyCredentialParameters(type: "public-key", alg: .algPS384)
        let options = try webAuthnManager.beginRegistration(
            user: user,
            publicKeyCredentialParameters: [publicKeyCredentialParameter]
        )

        XCTAssertEqual(options.challenge, challenge.base64EncodedString())
        XCTAssertEqual(options.rp.id, relyingPartyID)
        XCTAssertEqual(options.rp.name, relyingPartyDisplayName)
        XCTAssertEqual(options.timeout, timeout)
        XCTAssertEqual(options.user.id, user.userID.toBase64().asString())
        XCTAssertEqual(options.user.displayName, user.displayName)
        XCTAssertEqual(options.user.name, user.name)
        XCTAssertEqual(options.pubKeyCredParams, [publicKeyCredentialParameter])
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
        // {
        //   "fmt": "packed",
        //   "attStmt": {
        //     "alg": -7,
        //     "sig": h'3045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C'
        //   },
        //   "authData": 1
        // }
        let hexAttestationObjectWithInvalidAuthData: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YQE"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectWithInvalidAuthData),
            expect: WebAuthnError.invalidAuthData
        )
    }

    func testFinishRegistrationFailsIfFmtIsInvalid() async throws {
        // {
        //   "fmt": 1,
        //   "attStmt": {
        //     "alg": -7,
        //     "sig": h'3045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C'
        //   },
        //   "authData": h'49960DE5880E8C687434170F6476605B8FE4AEB9A28632C7995CF3BA831D97634500000000ADCE000235BCC60A648B0B25F1F0550300203A3EE56DCABABEC0EF2F4B7F0EE28E11317C2CF7FF972830440D63FCBAA7E26BA50102032620012158209AFFC8BA186D85A071FEDA41C77BA5C8D48FEDE8F1B89A7D6407DBC5A28D04AF2258203C8D8AAAA450DBA28AB85689D321FB9E8B8206BCC7BBCA9138D5BE08F6BD5433'
        // }
        let hexAttestationObjectWithInvalidFmt: URLEncodedBase64 = "o2NmbXQBZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIDo-5W3Kur7A7y9Lfw7ijhExfCz3_5coMEQNY_y6p-JrpQECAyYgASFYIJr_yLoYbYWgcf7aQcd7pcjUj-3o8biafWQH28WijQSvIlggPI2KqqRQ26KKuFaJ0yH7nouCBrzHu8qRONW-CPa9VDM"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectWithInvalidFmt),
            expect: WebAuthnError.invalidFmt
        )
    }

    func testFinishRegistrationFailsIfAttStmtIsMissing() async throws {
        // {
        //   "fmt": "packed",
        //   "authData": h'49960DE5880E8C687434170F6476605B8FE4AEB9A28632C7995CF3BA831D97634500000000ADCE000235BCC60A648B0B25F1F0550300203A3EE56DCABABEC0EF2F4B7F0EE28E11317C2CF7FF972830440D63FCBAA7E26BA50102032620012158209AFFC8BA186D85A071FEDA41C77BA5C8D48FEDE8F1B89A7D6407DBC5A28D04AF2258203C8D8AAAA450DBA28AB85689D321FB9E8B8206BCC7BBCA9138D5BE08F6BD5433'
        // }
        let hexAttestationObjectWithMissingAttStmt: URLEncodedBase64 = "omNmbXRmcGFja2VkaGF1dGhEYXRhWKRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAAArc4AAjW8xgpkiwsl8fBVAwAgOj7lbcq6vsDvL0t_DuKOETF8LPf_lygwRA1j_Lqn4mulAQIDJiABIVggmv_IuhhthaBx_tpBx3ulyNSP7ejxuJp9ZAfbxaKNBK8iWCA8jYqqpFDbooq4VonTIfuei4IGvMe7ypE41b4I9r1UMw"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectWithMissingAttStmt),
            expect: WebAuthnError.missingAttStmt
        )
    }

    func testFinishRegistrationFailsIfAuthDataIsTooShort() async throws {
        // {
        //   "fmt": "packed",
        //   "attStmt": {
        //     "alg": -7,
        //     "sig": h'3045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C'
        //   },
        //   "authData": h'49960D'
        // }
        let hexAttestationObjectInvalidAuthData: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YUNJlg0"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectInvalidAuthData),
            expect: WebAuthnError.authDataTooShort
        )
    }

    func testFinishRegistrationFailsIfAttestedCredentialDataFlagIsSetButThereIsNotCredentialData() async throws {
        // {
        //   "fmt": "packed",
        //   "attStmt": {
        //       "alg": -7,
        //       "sig": h'3045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C'
        //    },
        //    "authData": h'5647686C5647686C5647686C5647686C5647686C5647686C686C5647686C686C4000000000'
        // }
        let hexAttestationObjectMissingCredentialData: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVglVkdobFZHaGxWR2hsVkdobFZHaGxWR2hsaGxWR2hsaGxAAAAAAA"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectMissingCredentialData),
            expect: WebAuthnError.attestedCredentialDataMissing
        )
    }

    func testFinishRegistrationFailsIfAttestedCredentialDataFlagIsNotSetButThereIsCredentialData() async throws {
        // {
        //   "fmt": "packed",
        //   "attStmt": {
        //     "alg": -7,
        //     "sig": h'3045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C'
        //   },
        //   "authData": h'5647686C5647686C5647686C5647686C5647686C5647686C686C5647686C686C000000000000'
        // }
        let hexAttestationObjectWithCredentialData: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVgmVkdobFZHaGxWR2hsVkdobFZHaGxWR2hsaGxWR2hsaGwAAAAAAAA"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectWithCredentialData),
            expect: WebAuthnError.attestedCredentialFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfExtensionDataFlagIsSetButThereIsNoExtensionData() async throws {
        // {
        //   "fmt": "packed",
        //   "attStmt": {
        //     "alg": -7,
        //     "sig": h'3045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C'
        //   },
        //   "authData": h'5647686C5647686C5647686C5647686C5647686C5647686C686C5647686C686C8000000000'
        // }
        let hexAttestationObjectMissingExtensionData: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVglVkdobFZHaGxWR2hsVkdobFZHaGxWR2hsaGxWR2hsaGyAAAAAAA"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectMissingExtensionData),
            expect: WebAuthnError.extensionDataMissing
        )
    }

    func testFinishRegistrationFailsIfCredentialIdIsTooShort() async throws {
        // {
        //   "fmt": "packed",
        //   "attStmt": {
        //     "alg": -7,
        //     "sig": h'3045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C'
        //   },
        //   "authData": h'5647686C5647686C5647686C5647686C5647686C5647686C686C5647686C686C40000000005647686C5647686C5647686C5647686C00022A'
        // }
        let hexAttestationShortCredentialID: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVg4VkdobFZHaGxWR2hsVkdobFZHaGxWR2hsaGxWR2hsaGxAAAAAAFZHaGxWR2hsVkdobFZHaGwAAio"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationShortCredentialID),
            expect: WebAuthnError.credentialIDTooShort
        )
    }

    func testFinishRegistrationFailsIfCeremonyTypeDoesNotMatch() async throws {
        let clientDataJSONWrongCeremonyType = """
        {
            "type": "webauthn.get",
            "challenge": "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg",
            "origin": "http://localhost:8080",
            "crossOrigin": false,
            "other_keys_can_be_added_here": "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
        }
        """.toBase64().urlEncoded
        try await assertThrowsError(
            await finishRegistration(clientDataJSON: clientDataJSONWrongCeremonyType),
            expect: CollectedClientData.CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfChallengeDoesNotMatch() async throws {
        let clientDataJSONWrongChallenge = """
        {
            "type": "webauthn.create",
            "challenge": "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg",
            "origin": "http://localhost:8080",
            "crossOrigin": false,
            "other_keys_can_be_added_here": "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
        }
        """.toBase64().urlEncoded
        try await assertThrowsError(
            await finishRegistration(
                challenge: "definitelyAnotherChallenge",
                clientDataJSON: clientDataJSONWrongChallenge
            ),
            expect: CollectedClientData.CollectedClientDataVerifyError.challengeDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfOriginDoesNotMatch() async throws {
        let clientDataJSONWrongOrigin: URLEncodedBase64 = """
        {
            "type": "webauthn.create",
            "challenge": "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg",
            "origin": "http://johndoe.com",
            "crossOrigin": false,
            "other_keys_can_be_added_here": "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
        }
        """.toBase64().urlEncoded
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
        // {
        //   "fmt": "packed",
        //   "attStmt": {
        //     "alg": -7,
        //     "sig": h'3045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C'
        //   },
        //   "authData": h'49960DE5880E8C687434170F6476605B8FE4AEB9A28632C7995CF3BA831D97634500000000ADCE000235BCC60A648B0B25F1F0550300013A'
        // }
        let hexAttestationObjectMismatchingRpId: URLEncodedBase64 = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVg4SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAATo"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectMismatchingRpId),
            expect: WebAuthnError.relyingPartyIDHashDoesNotMatch
        )
    }

    func testFinishRegistrationFailsIfUserPresentFlagIsNotSet() async throws {
        // {
        //   "fmt": "none",
        //   "attStmt": {},
        //   "authData": h'74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef04400000000adce000235bcc60a648b0b25f1f055030020508b5e92512a9c9d89ea977d04e6f4f6db35e9f6c841661173e6eb177f817d58a501020326200121582088c51237af0c14c157fe71d2e0a57f693d432b9945c1ec60bf0a17378cca83a2225820f968b5de6d8dd1c71ebc229b86895639e7801a0767a30b57b585a542eef7638e'
        // }
        let hexAttestationObjectUPFlagNotSet: URLEncodedBase64 = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBEAAAAAK3OAAI1vMYKZIsLJfHwVQMAIFCLXpJRKpydieqXfQTm9PbbNen2yEFmEXPm6xd_gX1YpQECAyYgASFYIIjFEjevDBTBV_5x0uClf2k9QyuZRcHsYL8KFzeMyoOiIlgg-Wi13m2N0ccevCKbholWOeeAGgdnowtXtYWlQu73Y44"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectUPFlagNotSet),
            expect: WebAuthnError.userPresentFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfUserVerificationFlagIsNotSetButRequired() async throws {
        // {
        //   "fmt": "none",
        //   "attStmt": {},
        //   "authData": h'74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef04100000000adce000235bcc60a648b0b25f1f055030020508b5e92512a9c9d89ea977d04e6f4f6db35e9f6c841661173e6eb177f817d58a501020326200121582088c51237af0c14c157fe71d2e0a57f693d432b9945c1ec60bf0a17378cca83a2225820f968b5de6d8dd1c71ebc229b86895639e7801a0767a30b57b585a542eef7638e'
        // }
        let hexAttestationObjectUVFlagNotSet: URLEncodedBase64 = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAK3OAAI1vMYKZIsLJfHwVQMAIFCLXpJRKpydieqXfQTm9PbbNen2yEFmEXPm6xd_gX1YpQECAyYgASFYIIjFEjevDBTBV_5x0uClf2k9QyuZRcHsYL8KFzeMyoOiIlgg-Wi13m2N0ccevCKbholWOeeAGgdnowtXtYWlQu73Y44"
        try await assertThrowsError(
            await finishRegistration(
                attestationObject: hexAttestationObjectUVFlagNotSet,
                requireUserVerification: true
            ),
            expect: WebAuthnError.userVerificationRequiredButFlagNotSet
        )
    }

    func testFinishRegistrationFailsIfAttFmtIsNoneButAttStmtIsIncluded() async throws {
        // {
        //   "fmt": "none",
        //   "attStmt": { "hello": "world" },
        //   "authData": h'74A6EA9213C99C2F74B22492B320CF40262A94C1A950A0397F29250B60841EF04500000000ADCE000235BCC60A648B0B25F1F055030020508B5E92512A9C9D89EA977D04E6F4F6DB35E9F6C841661173E6EB177F817D58A501020326200121582088C51237AF0C14C157FE71D2E0A57F693D432B9945C1EC60BF0A17378CCA83A2225820F968B5DE6D8DD1C71EBC229B86895639E7801A0767A30B57B585A542EEF7638E'
        // }
        let hexAttestationObjectAttStmtNoneWithAttStmt: URLEncodedBase64 = "o2NmbXRkbm9uZWdhdHRTdG10oWVoZWxsb2V3b3JsZGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIFCLXpJRKpydieqXfQTm9PbbNen2yEFmEXPm6xd_gX1YpQECAyYgASFYIIjFEjevDBTBV_5x0uClf2k9QyuZRcHsYL8KFzeMyoOiIlgg-Wi13m2N0ccevCKbholWOeeAGgdnowtXtYWlQu73Y44"
        try await assertThrowsError(
            await finishRegistration(attestationObject: hexAttestationObjectAttStmtNoneWithAttStmt),
            expect: WebAuthnError.attestationStatementMustBeEmpty
        )
    }

    func testFinishRegistrationFailsIfRawIDIsTooLong() async throws {
        try await assertThrowsError(
            await finishRegistration(rawID: [UInt8](repeating: 0, count: 1024).base64EncodedString().urlEncoded),
            expect: WebAuthnError.credentialRawIDTooLong
        )
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

    // decoded clientDataJSON:
    // {
    //   "type": "webauthn.create",
    //   "challenge": "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg",
    //   "origin": "https://example.com",
    //   "crossOrigin": false,
    //   "other_keys_can_be_added_here": "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
    // }
    //
    // decoded attestationObject:
    // {
    //   "fmt": "none",
    //   "attStmt": {},
    //   "authData": h'74A6EA9213C99C2F74B22492B320CF40262A94C1A950A0397F29250B60841EF04500000000ADCE000235BCC60A648B0B25F1F055030020508B5E92512A9C9D89EA977D04E6F4F6DB35E9F6C841661173E6EB177F817D58A501020326200121582088C51237AF0C14C157FE71D2E0A57F693D432B9945C1EC60BF0A17378CCA83A2225820F968B5DE6D8DD1C71EBC229B86895639E7801A0767A30B57B585A542EEF7638E'
    // }
    private func finishRegistration(
        challenge: EncodedBase64 = "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg", // "randomStringFromServer"
        id: EncodedBase64 = "4PrJNQUJ9xdI2DeCzK9rTBRixhXHDiVdoTROQIh8j80",
        type: String = "public-key",
        rawID: URLEncodedBase64 = "4PrJNQUJ9xdI2DeCzK9rTBRixhXHDiVdoTROQIh8j80",
        clientDataJSON: URLEncodedBase64 = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9",
        attestationObject: URLEncodedBase64 = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIFCLXpJRKpydieqXfQTm9PbbNen2yEFmEXPm6xd_gX1YpQECAyYgASFYIIjFEjevDBTBV_5x0uClf2k9QyuZRcHsYL8KFzeMyoOiIlgg-Wi13m2N0ccevCKbholWOeeAGgdnowtXtYWlQu73Y44",
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
