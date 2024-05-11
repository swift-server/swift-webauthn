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
final class RegistrationAndroidKeyAttestationTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!

    //let challenge: [UInt8] = Array(Data(base64Encoded: "kIgdIQmaAms56UNzw0DH8uOz3BDF2UJYaJP6zIQX1a8=")!)
    
    let relyingPartyDisplayName = "Testy test"
    let relyingPartyID = "example.com"
    let relyingPartyOrigin = "https://example.com"
    let mockClientDataJSONBytes = TestClientDataJSON(challenge: TestConstants.mockChallenge.base64URLEncodedString()).jsonBytes
    let mockCredentialPublicKeyECC = TestCredentialPublicKeyBuilder().validMock().buildAsByteArray()
    let challenge: [UInt8] = [1, 0, 1]

    override func setUp() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: relyingPartyID,
            relyingPartyName: relyingPartyDisplayName,
            relyingPartyOrigin: relyingPartyOrigin
        )
        webAuthnManager = .init(configuration: configuration, challengeGenerator: .mock(generate: challenge))
    }

    func testInvalidAlg() async throws {
        //let authData = TestAuthDataBuilder().validMock()
        let authData = TestAuthDataBuilder().validMock()
            .attestedCredData(credentialPublicKey: mockCredentialPublicKeyECC)
            .noExtensionData()
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.androidKey)
            .authData(authData)
            .attStmt(
                .map([.utf8String("alg"): .negativeInt(999)])
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

    func testInvalidSig() async throws {
        let authData = TestAuthDataBuilder().validMock()
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.androidKey)
            .authData(authData)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algES256.rawValue) - 1)),
                    .utf8String("sig"): .negativeInt(999)
                ])
            )
            .build()
            .cborEncoded
        
        await assertThrowsError(
            try await finishRegistration(
                attestationObject: mockAttestationObject,
                rootCertificatesByFormat: [:]
            ),
            expect: WebAuthnError.invalidSignature
        )
    }
    
    func testInvalidCert() async throws {
        let authData = TestAuthDataBuilder().validMock()
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.androidKey)
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
    
    func testInvalidVerificationData() async throws {
        let mockCerts = try TestECCKeyPair.certificates()
        let verificationData: [UInt8] = [0x01]
        let authData = TestAuthDataBuilder().validMock()
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.androidKey)
            .authData(authData)
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
                rootCertificatesByFormat: [:]
            ),
            expect: WebAuthnError.invalidVerificationData
        )
    }
    
    func testPublicKeysMismatch() async throws {
        let mockCerts = try TestECCKeyPair.certificates()
        let authData = TestAuthDataBuilder().validMockRSA()
        let clientDataHash = SHA256.hash(data: Data(mockClientDataJSONBytes))
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.androidKey)
            .authData(authData)
            .attStmt(
                .map([
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algES256.rawValue) - 1)),
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair
                            .signature(data: Data(authData.build().byteArrayRepresentation) + clientDataHash)
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
                rootCertificatesByFormat: [:]
            ),
            expect: WebAuthnError.attestationPublicKeyMismatch
        )
    }

    // TODO: add test for successful attestation verification

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
