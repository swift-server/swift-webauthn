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
final class RegistrationTPMAttestationTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!

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
    }

    func testAttCAAttestationRSASucceeds() async throws {
        let mockCredentialPublicKey = TestCredentialPublicKeyBuilder().validMockRSA().buildAsByteArray()
        let authData = TestAuthDataBuilder().validMock()
            .attestedCredData(credentialPublicKey: mockCredentialPublicKey)
            .noExtensionData()
        let hash = SHA256.hash(data: Data(mockClientDataJSONBytes))
        let mockCerts = try TestECCKeyPair.certificates()
        
        //let certInfoBytes: [UInt8] = [0xFF, 0x54, 0x43, 0x47] + [UInt8](repeating: 0, count: 80)
        // RSA PubArea
        let pubArea = Data(base64Encoded: "AAEACwAGBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAEAgAAAAAAAEAus2NNibjf6n9vIlQiEmunemlDObEtj7Cr2TDtD//tvJS1//fsW5mxHEz7wo+WiBKlVHwm9O1OKggQVHWlsoAG4QHJL82KwApuSPIYzKBpMTJGS8OZF9Eo7R8elX4JLBJcZ7uA3AtoPaai/zHIHXWVdMzRq2DY9Ymps6MU8jnGMr2Y0L/+IFPrfZhHNLqhx7/h+pNt6eJnp7MmhgIZBk1fKHcgcbDaXZ0fCD511jzu7QQ025OJoN1bXJai4UtPkwof0J2epXBJdu8ExPBY8KlXUBvRdTrsp/njQAKtBLn288I0jabg65Y/io+cWP5UuQTBI0FF6j/lOZ81ttk3oV/FQ==")!
        let certInfo = Data(base64Encoded: "/1RDR4AXACIAC7fjlRE/X84oQtXc8hucRu9DFXUZD6UhJFkNJ57OM2mJABRqOl417tyWPsLqfhByWFhLi6W+OQAAAAjIGcaOvjsE9fnCGcEBo17KdHVMLNYAIgAL8wrHq55UwHsBdEMDTgPolqcoRsQvpP8QUY07Rjc/ZuoAIgALOeLcnM1NWggIfzd1ct6nAJwvcxnjsbUECgnvAgGp22w=")!
        let mockAttestationObject = TestAttestationObjectBuilder()
            .validMock()
            .fmt(.tpm)
            .authData(authData)
            .attStmt(
                .map([
                    .utf8String("ver"): .utf8String("2.0"),
                    .utf8String("alg"): .negativeInt(UInt64(abs(COSEAlgorithmIdentifier.algRS256.rawValue) - 1)),
                    .utf8String("sig"): .byteString(Array(
                        try TestECCKeyPair
                            .signature(data: Data(authData.build().byteArrayRepresentation) + hash)
                            .derRepresentation
                    )),
                    .utf8String("x5c"): .array([.byteString(Array(mockCerts.leaf))]),
                    .utf8String("aikCert"): .byteString(Array(mockCerts.leaf)),
                    .utf8String("pubArea"): .byteString(Array(pubArea)),
                    .utf8String("certInfo"): .byteString(Array(certInfo)),
                ])
            )
            .build()
            .cborEncoded

        let credential = try await finishRegistration(
            attestationObject: mockAttestationObject,
            rootCertificatesByFormat: [.tpm: [mockCerts.ca]]
        )
        XCTAssertEqual(credential.attestationResult.format, .tpm)
        XCTAssertEqual(credential.attestationResult.type, .attCA)
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
