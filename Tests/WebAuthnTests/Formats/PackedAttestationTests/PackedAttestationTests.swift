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
import _CryptoExtras
import X509

// swiftlint:disable:next type_body_length
final class RegistrationPackedAttestationTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!
    var authDataECC: TestAuthDataBuilder!
    var authDataRSA: TestAuthDataBuilder!
    var clientDataHash: SHA256.Digest!
    
    let challenge: [UInt8] = [1, 0, 1]
    let relyingPartyDisplayName = "Testy test"
    let relyingPartyID = "example.com"
    let relyingPartyOrigin = "https://example.com"
    let mockClientDataJSONBytes = TestClientDataJSON(challenge: TestConstants.mockChallenge.base64URLEncodedString()).jsonBytes

    override func setUp() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: relyingPartyID,
            relyingPartyName: relyingPartyDisplayName,
            relyingPartyOrigin: relyingPartyOrigin
        )
        webAuthnManager = .init(configuration: configuration, challengeGenerator: .mock(generate: challenge))
        let mockCredentialPublicKeyECC = TestCredentialPublicKeyBuilder().validMock().buildAsByteArray()
        authDataECC = TestAuthDataBuilder().validMock()
            .attestedCredData(credentialPublicKey: mockCredentialPublicKeyECC)
            .noExtensionData()
        let mockCredentialPublicKeyRSA = TestCredentialPublicKeyBuilder().validMockRSA().buildAsByteArray()
        authDataRSA = TestAuthDataBuilder().validMock()
            .attestedCredData(credentialPublicKey: mockCredentialPublicKeyRSA)
            .noExtensionData()
        
        clientDataHash = SHA256.hash(data: Data(mockClientDataJSONBytes))
    }

    func testInvalidAlg() async throws {
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.packed)
            .authData(authDataECC)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(999),
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair
                            .signature(data: Data(authDataECC.build().byteArrayRepresentation) + clientDataHash)
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
            expect: WebAuthnError.invalidAttestationSignatureAlgorithm
        )
    }
    
    func testSelfAttestationAlgMismatch() async throws {
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.packed)
            .authData(authDataECC)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algES384.rawValue) - 1)),
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair
                            .signature(data: Data([0x01])).derRepresentation
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
            expect: WebAuthnError.attestationPublicKeyAlgorithmMismatch
        )
    }

    func testInvalidCert() async throws {
        let authData = TestAuthDataBuilder().validMock()
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.packed)
            .authData(authData)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algES256.rawValue) - 1)),
                    .utf8String("sig"): .byteString([0x00]),
                    .utf8String("x5c"): .byteString([0x00])
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

    func testBasicAttestationInvalidVerifData() async throws {
        let verificationData: [UInt8] = [0x01]
        let mockCerts = try TestECCKeyPair.certificates()
        
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.packed)
            .authData(authDataECC)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algES256.rawValue) - 1)),
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair
                            .signature(data: Data(verificationData))
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
                rootCertificatesByFormat: [.packed: [mockCerts.ca]]
            ),
            expect: WebAuthnError.invalidVerificationData
        )
    }
    
    func testBasicAttestationInvalidTrustPath() async throws {
        let mockCerts = try TestECCKeyPair.certificates()
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.packed)
            .authData(authDataECC)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algES256.rawValue) - 1)),
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair
                            .signature(data: Data(authDataECC.build().byteArrayRepresentation) + clientDataHash)
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
                rootCertificatesByFormat: [.packed: []]
            ),
            expect: WebAuthnError.invalidTrustPath
        )
    }

    func testSelfAttestationECCSucceeds() async throws {
        let mockAttestationObject = TestAttestationObjectBuilder()
            .validMock()
            .fmt(.packed)
            .authData(authDataECC)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algES256.rawValue) - 1)),
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair
                            .signature(data: Data(authDataECC.build().byteArrayRepresentation) + clientDataHash)
                            .derRepresentation
                    ))
                ])
            )
            .build()
            .cborEncoded

        let credential = try await finishRegistration(attestationObject: mockAttestationObject)
        XCTAssertEqual(credential.attestationResult.format, .packed)
        XCTAssertEqual(credential.attestationResult.type, .`self`)
        XCTAssertEqual(credential.attestationResult.trustChain, [])
    }
    
    func testBasicAttestationECCSucceeds() async throws {
        let mockCerts = try TestECCKeyPair.certificates()
        let mockAttestationObject = TestAttestationObjectBuilder()
            .validMock()
            .fmt(.packed)
            .authData(authDataECC)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algES256.rawValue) - 1)),
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair
                            .signature(data: Data(authDataECC.build().byteArrayRepresentation) + clientDataHash)
                            .derRepresentation
                    )),
                    .utf8String("x5c"): .array([.byteString(Array(mockCerts.leaf))])
                ])
            )
            .build()
            .cborEncoded

        let credential = try await finishRegistration(
            attestationObject: mockAttestationObject,
            rootCertificatesByFormat: [.packed: [mockCerts.ca]]
        )
        XCTAssertEqual(credential.attestationResult.format, .packed)
        XCTAssertEqual(credential.attestationResult.type, .basicFull)
        XCTAssertEqual(credential.attestationResult.trustChain.count, 2)
    }
    
    func testSelfPackedAttestationRSASucceeds() async throws {
        let mockAttestationObject = TestAttestationObjectBuilder()
            .validMock()
            .fmt(.packed)
            .authData(authDataRSA)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algRS256.rawValue) - 1)),
                    .utf8String("sig"): .byteString(Array(
                        try TestRSAKeyPair
                            .signature(data: Data(authDataRSA.build().byteArrayRepresentation) + clientDataHash)
                            .rawRepresentation
                    ))
                ])
            )
            .build()
            .cborEncoded

        let credential = try await finishRegistration(attestationObject: mockAttestationObject)

        XCTAssertEqual(credential.attestationResult.format, .packed)
        XCTAssertEqual(credential.attestationResult.type, .`self`)
        XCTAssertEqual(credential.attestationResult.trustChain, [])
    }
    
    func testBasicPackedAttestationRSASucceeds() async throws {
        let mockCerts = try TestRSAKeyPair.certificates()
        let mockAttestationObject = TestAttestationObjectBuilder()
            .validMock()
            .fmt(.packed)
            .authData(authDataRSA)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algRS256.rawValue) - 1)),
                    .utf8String("sig"): .byteString(Array(
                        try TestRSAKeyPair
                            .signature(data: Data(authDataRSA.build().byteArrayRepresentation) + clientDataHash)
                            .rawRepresentation
                    )),
                    .utf8String("x5c"): .array([
                        .byteString(Array(mockCerts.leaf))
                    ])
                ])
            )
            .build()
            .cborEncoded

        let credential = try await finishRegistration(
            attestationObject: mockAttestationObject,
            rootCertificatesByFormat: [.packed: [mockCerts.ca]]
        )

        XCTAssertEqual(credential.attestationResult.format, .packed)
        XCTAssertEqual(credential.attestationResult.type, .basicFull)
        XCTAssertEqual(credential.attestationResult.trustChain.count, 2)
    }

    private func finishRegistration(
        challenge: [UInt8] = TestConstants.mockChallenge,
        type: CredentialType = .publicKey,
        rawID: [UInt8] = "e0fac9350509f71748d83782ccaf6b4c1462c615c70e255da1344e40887c8fcd".hexadecimal!,
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
