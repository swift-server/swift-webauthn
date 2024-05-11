//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2023 the WebAuthn Swift project authors
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
import X509

// swiftlint:disable:next type_body_length
final class RegistrationFidoU2FAttestationTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!

    let challenge: [UInt8] = [1, 0, 1]
    let relyingPartyDisplayName = "Testy test"
    let relyingPartyID = "example.com"
    let relyingPartyOrigin = "https://example.com"
    static let credentialId = "e0fac9350509f71748d83782ccaf6b4c1462c615c70e255da1344e40887c8fcd".hexadecimal!
    let mockClientDataJSONBytes = TestClientDataJSON(challenge: TestConstants.mockChallenge.base64URLEncodedString()).jsonBytes

    override func setUp() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: relyingPartyID,
            relyingPartyName: relyingPartyDisplayName,
            relyingPartyOrigin: relyingPartyOrigin
        )
        webAuthnManager = .init(configuration: configuration, challengeGenerator: .mock(generate: challenge))
    }

    func testAttestationInvalidVerifData() async throws {
        let authData = TestAuthDataBuilder().validMock()
        // invalid verification data
        let verificationData: [UInt8] = [0x00, 0x01]
        let mockCerts = try TestECCKeyPair.certificates()
        
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.fidoU2F)
            .authData(authData)
            .attStmt(
                .map([
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair.signature(data: Data(verificationData))
                            .derRepresentation
                    )),
                    .utf8String("x5c"): .array([.byteString(Array(mockCerts.leaf))])
                ])
            )
            .build()
            .cborEncoded

        await assertThrowsError(
            try await finishRegistration(
                attestationObject: mockAttestationObject,
                rootCertificatesByFormat: [.fidoU2F: [mockCerts.ca]]
            ),
            expect: WebAuthnError.invalidVerificationData
        )
    }
    
    func testAttestationMissingx5c() async throws {
        let authData = TestAuthDataBuilder().validMock()        
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.fidoU2F)
            .authData(authData)
            .attStmt(
                .map([
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair.signature(data: Data([0x00, 0x01]))
                            .derRepresentation
                    )),
                ])
            )
            .build()
            .cborEncoded

        await assertThrowsError(
            try await finishRegistration(
                attestationObject: mockAttestationObject,
                rootCertificatesByFormat: [:]
            ),
            expect: WebAuthnError.invalidAttestationCertificate
        )
    }

    func testBasicAttestationSucceeds() async throws {
        let mockCerts = try TestECCKeyPair.certificates()
        let credentialId: [UInt8] = [0b00000001]
        let authData = TestAuthDataBuilder()
            .relyingPartyIDHash(fromRelyingPartyID: relyingPartyID)
            .flags(0b11000101)
            .counter([0b00000000, 0b00000000, 0b00000000, 0b00000000])
            .attestedCredData(
                aaguid: [UInt8](repeating: 0, count: 16),
                credentialIDLength: [0b00000000, 0b00000001],
                credentialID: credentialId,
                credentialPublicKey: TestCredentialPublicKeyBuilder().validMock().buildAsByteArray()
            )
            .extensions([UInt8](repeating: 0, count: 20))
       
        let rpIdHash = SHA256.hash(data: Data(self.relyingPartyID.utf8))
        let clientDataHash = SHA256.hash(data: mockClientDataJSONBytes)
        // With U2F, the public key used when calculating the signature (`sig`) is encoded in ANSI X9.62 format
        let publicKeyU2F: [UInt8] = [0x04] + TestECCKeyPair.publicKeyXCoordinate + TestECCKeyPair.publicKeyYCoordinate
        // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
        let verificationData: [UInt8] = [0x00] + rpIdHash + clientDataHash + credentialId + publicKeyU2F
        
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.fidoU2F)
            .authData(authData)
            .attStmt(
                .map([
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair.signature(data: Data(verificationData))
                            .derRepresentation
                    )),
                    .utf8String("x5c"): .array([.byteString(Array(mockCerts.leaf))])
                ])
            )
            .build()
            .cborEncoded

        let credential = try await finishRegistration(
            attestationObject: mockAttestationObject,
            rootCertificatesByFormat: [.fidoU2F: [mockCerts.ca]]
        )
        XCTAssertEqual(credential.attestationResult.format, .fidoU2F)
        XCTAssertEqual(credential.attestationResult.type, .basicFull)
        XCTAssertEqual(credential.attestationResult.trustChain.count, 2)
    }

    private func finishRegistration(
        challenge: [UInt8] = TestConstants.mockChallenge,
        type: CredentialType = .publicKey,
        rawID: [UInt8] = credentialId,
        attestationObject: [UInt8],
        requireUserVerification: Bool = false,
        rootCertificatesByFormat: [AttestationFormat: [Certificate]] = [:],
        confirmCredentialIDNotRegisteredYet: (String) async throws -> Bool = { _ in true }
    ) async throws -> Credential {
        try await webAuthnManager.finishRegistration(
            challenge: challenge,
            credentialCreationData: RegistrationCredential(
                id: rawID.base64URLEncodedString(),
                type: type,
                rawID: rawID,
                attestationResponse: AuthenticatorAttestationResponse(
                    clientDataJSON: mockClientDataJSONBytes,
                    attestationObject: attestationObject
                )
            ),
            requireUserVerification: requireUserVerification,
            rootCertificatesByFormat: rootCertificatesByFormat,
            confirmCredentialIDNotRegisteredYet: confirmCredentialIDNotRegisteredYet
        )
    }
}
