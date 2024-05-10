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
final class RegistrationTPMAttestationTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!

    let challenge: [UInt8] = Array(Data(base64Encoded: "kIgdIQmaAms56UNzw0DH8uOz3BDF2UJYaJP6zIQX1a8=")!)
    let relyingPartyDisplayName = "Testy test"
    let relyingPartyID = "d2urpypvrhb05x.amplifyapp.com"
    let relyingPartyOrigin = "https://dev.d2urpypvrhb05x.amplifyapp.com"

    // Generating data, or mocking it, for a TPM registration, would be excruciatingly painful.
    // Here we're using a "known good payload" for a Windows Hello authenticator.
    let clientDataJSONBase64 = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoia0lnZElRbWFBbXM1NlVOencwREg4dU96M0JERjJVSllhSlA2eklRWDFhOCIsIm9yaWdpbiI6Imh0dHBzOi8vZGV2LmQydXJweXB2cmhiMDV4LmFtcGxpZnlhcHAuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="
    let attestationObjectBase64 = URLEncodedBase64("o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQBFEaTe-uZvbZBNsIMtJa26eigMUxEM1mBtddR7gdEBH5Hyeo9hFCqiJwYVKUq_iP9hvFaiLzoGbAWDgiG-fa3F-S71c8w83756dyRBMXNHYEvYjfv0TqGyky73V4xyKpf1iHiO_g4t31UjQiyTfypdP_rRcm42KVKgVyRPZzx_AKweN9XKEFfT2Ym3fmqD_scaIeKSyGs9qwH1MbILLUVnRK6fKK6sAA4ZaDVz4gUiSUoK9ZycCC2hfLBq5GjiTLgQF_Q2O3gRTqmU8VfwVsmtN5OMaGOyaFrUk97-RvZVrARXhNzrUAJT7KjTLDZeIA96F3pB_F_q3xd_dgvwVpWHY3ZlcmMyLjBjeDVjglkFuzCCBbcwggOfoAMCAQICEHHcna7VCE3QpRyKgi2uvXYwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLU5UQy1LRVlJRC04ODJGMDQ3Qjg3MTIxQ0Y5ODg1RjMxMTYwQkM3QkI1NTg2QUY0NzFCMB4XDTIyMDEyMDE5NTQxNloXDTI3MDYwMzE3NTE0OFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtT5frDB-WUq6N0VYnlYEalJzSut0JQx3vP29_ub-kZ7csJrm8uGXQGUkPlf4EFehFTnQ1jX_oZ8jNPw1m3rV5ijcuCe3r5GICFD6gpbuErmGS2mDVfe3fl_p0gPvhtulqatb1uYkWfW5SIKix1XWRvm92s3lRQvd-6vX_ExPIP-pEf0tkeINpBNNWgdtx3VdW4KVFTcv-q2FKhqfqXiAdOMHmwmWyXYulppYqW2XC7Pw9QmHZR_C5Urpc5UMmABz4zWSAYOyBMkKsX8koAsk8RgLtus07wW3FhJqi-BYczIe0IxG0q9UL295lkaxreTkfWYZHMMcU4M-Tm1w7QvKsCAwEAAaOCAeowggHmMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFAGA1UdEQEB_wRGMESkQjBAMT4wEAYFZ4EFAgIMB05QQ1Q3NXgwFAYFZ4EFAgEMC2lkOjRFNTQ0MzAwMBQGBWeBBQIDDAtpZDowMDA3MDAwMjAfBgNVHSMEGDAWgBSMmnF_AA0xD8rW7i0pqjSXJYwSHjAdBgNVHQ4EFgQUFmUMIda76eb7Whi8CweaWhe7yNMwgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1udGMta2V5aWQtODgyZjA0N2I4NzEyMWNmOTg4NWYzMTE2MGJjN2JiNTU4NmFmNDcxYi84ODIzMGNhMi0yN2U1LTQxNTEtOWJhMi01OWI1ODJjMzlhYWEuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQCxsTbR5V8qnw6H6HEWJvrqcRy8fkY_vFUSjUq27hRl0t9D6LuS20l65FFm48yLwCkQbIf-aOBjwWafAbSVnEMig3KP-2Ml8IFtH63Msq9lwDlnXx2PNi7ISOemHNzBNeOG7pd_Zs69XUTq9zCriw9gAILCVCYllBluycdT7wZdjf0Bb5QJtTMuhwNXnOWmjv0VBOfsclWo-SEnnufaIDi0Vcf_TzbgmNn408Ej7R4Njy4qLnhPk64ruuWNJt3xlLMjbJXe_VKdO3lhM7JVFWSNAn8zfvEIwrrgCPhp1k2mFUGxJEvpSTnuZtNF35z4_54K6cEqZiqO-qd4FKt4KYs1GYJDyxttuUySGtnYyZg2aYB6hamg3asRDjBMPqoURsdVJcWQh3dFnD88cbs7Qt4_ytqAY61qfPE7bJ6E33o0X7OtxmECPd3aBJk6nsyXEXNF2vIww1UCrRC0OEr1HsTqA4bQU8KCWV6kduUnvkUWPT8CF0d2ER4wnszb053Tlcf2ebcytTMf_Nd95g520Hhqb2FZALCErijBi04Bu6SNeND1NQ3nxDSKC-CamOYW0ODch05Xzi1V0_sq0zmdKTxMSpg1jOZ1Q9924D4lJkruCB3zcsIBTUxV0EgAM1zGuoqwWjwYXr_8tO4_kEO1Lw8DckZIrk1s3ySsMVC89TRrIVkG7zCCBuswggTToAMCAQICEzMAAAQI5W53M7IUDf4AAAAABAgwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMTA2MDMxNzUxNDhaFw0yNzA2MDMxNzUxNDhaMEExPzA9BgNVBAMTNkVVUy1OVEMtS0VZSUQtODgyRjA0N0I4NzEyMUNGOTg4NUYzMTE2MEJDN0JCNTU4NkFGNDcxQjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMEye3QdCUOGeseHj_QjLMJVbHBEJKkRbXFsmZi6Mob_3IsVfxO-mQQC-xfY9tDyB1jhxfFAG-rjUfRVBwYYPfaVo2W58Q09Kcpf-43Iw9SRxx2ThP-KPFJPFBofZroloNaTNz3DRaWZ2ha-_PUG2nwTXR7LoIpqMVW1PDzGxb47SNpRmKJxVZhQ2_wRhZZvHRHJpZmrCmHRpTRqWSzQT1jn7Zo9VuMYvp_OFj7-LFpkqi4BYyhi0kTBPDQTpYrBi7RtmF1MhZBmm1HGDhoXHcPSZkN5vq5at4g03R15KWyRDgBcckCAgtewd6Dtd_Zwaejlm57xyGqP6T-AE-N8udh1NPv_PZVlSc4CnCayUTPORuaJ7N-v7Y4wpNSIdipq29hw19WVuO_z7q6GpQbn17arYf6LSoDZfwO8GHXPrtBOYYSZCNKuZ_IK8nomBLJPtN5AzwEZNyLCZIkg0U0sJ-oVr2UEYxlwwZQm5RSDxProaKU-OXq4f_j_0pEu5_DbJx9syR3Nsv6Lt9Zkf3JSJTVtWXoM0-R_82vAJ669PX0LLr603PKWBZbW7zQvtGojT_Pc1FDGfwhcdckxd3MGpEjZwh_1D8elYcxj3Ndw5jClWosZKr33pUcjqeFtSZSur0lbm6vyCfS16XzSMn8IkHmbbXcpgGKHumUCFD8CHJIBAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBSMmnF_AA0xD8rW7i0pqjSXJYwSHjAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAHG-1grb-6xpObMtxfFScl8PRLd_GjLFaeAd0kVPls0jzKplG2Am4O87Qg0OUY0VhQ-uD39590gGrWEWnOmdrVJ-R1lJc1yrIZFEASBEedJSvxw9YTNknD59uXtznIP_4Glk-4NpqpcYov2OkBdV59V4dTL5oWFH0vzkZQfvGFxEHwtB9O6Bh0Lk142zXAh5_vf_-hSw3t9adloBAnA0AtPUVkzmgNRGeTpfPm-Iud-MAoUXaccFn2EChjKb9ApbS1ww8ZvX4x2kFU6qctu32g7Vf6CgACc1i-UYDT_E-h6c1O4n7JK2OxVS-DVwybps-cALU0gj-ZMauNMej0_x_NerzvDuQ77eFMTDMY4ZTzYOzlg4Nj0K8y1Bx_KqeTBO0N9CdEG3dBxWCUUFQzAx-i38xJL-dtYTCCFATVhc9FFJ0CQgU07JAGAeuNm_GL8kN46bMXd_ApQYFzDQUWYYXvRIt9mCw0Zd45lpAMuiDKT9TgjUVDNu8LQ8FPK0KeiQVrGHFMhHgg2pbVH9Pvc1jNEeRpCo0BLpZQwuIgEt90mepkt6Va-C9krHsU4y2oalG2LUu-jOC3NWNK8LssYVUCFWtaKh5d-xdTQmjx4uO-1sq9GFntVJ94QnEDhldz0XMopQ8srTGLMqR3MT-GkSNb5X1UFC-X1udXI8YvB3ADr_Z3B1YkFyZWFZATYAAQALAAYEcgAgnf_L82w4OuaZ-5ho3G3LidcVOIS-KAOSLBJBWL-tIq4AEAAQCAAAAAAAAQC6zY02JuN_qf28iVCISa6d6aUM5sS2PsKvZMO0P_-28lLX_9-xbmbEcTPvCj5aIEqVUfCb07U4qCBBUdaWygAbhAckvzYrACm5I8hjMoGkxMkZLw5kX0SjtHx6VfgksElxnu4DcC2g9pqL_McgddZV0zNGrYNj1iamzoxTyOcYyvZjQv_4gU-t9mEc0uqHHv-H6k23p4mensyaGAhkGTV8odyBxsNpdnR8IPnXWPO7tBDTbk4mg3VtclqLhS0-TCh_QnZ6lcEl27wTE8FjwqVdQG9F1Ouyn-eNAAq0EufbzwjSNpuDrlj-Kj5xY_lS5BMEjQUXqP-U5nzW22TehX8VaGNlcnRJbmZvWKH_VENHgBcAIgALt-OVET9fzihC1dzyG5xG70MVdRkPpSEkWQ0nns4zaYkAFGo6XjXu3JY-wup-EHJYWEuLpb45AAAACMgZxo6-OwT1-cIZwQGjXsp0dUws1gAiAAvzCsernlTAewF0QwNOA-iWpyhGxC-k_xBRjTtGNz9m6gAiAAs54tyczU1aCAh_N3Vy3qcAnC9zGeOxtQQKCe8CAanbbGhhdXRoRGF0YVkBZ-MWwK8fdtoeGn4DEn0TAUu4IUP_PMiBiJd4lDRznbBDRQAAAAAImHBYytxLgbbhMN5Q3L6WACBxLUIzn9ngKAM11_UwWG7kCiAvVyO1mYGSsEhfWeyhDaQBAwM5AQAgWQEAus2NNibjf6n9vIlQiEmunemlDObEtj7Cr2TDtD__tvJS1__fsW5mxHEz7wo-WiBKlVHwm9O1OKggQVHWlsoAG4QHJL82KwApuSPIYzKBpMTJGS8OZF9Eo7R8elX4JLBJcZ7uA3AtoPaai_zHIHXWVdMzRq2DY9Ymps6MU8jnGMr2Y0L_-IFPrfZhHNLqhx7_h-pNt6eJnp7MmhgIZBk1fKHcgcbDaXZ0fCD511jzu7QQ025OJoN1bXJai4UtPkwof0J2epXBJdu8ExPBY8KlXUBvRdTrsp_njQAKtBLn288I0jabg65Y_io-cWP5UuQTBI0FF6j_lOZ81ttk3oV_FSFDAQAB")
  
    // Windows Hello CA
    let caCert = try! Certificate(
        derEncoded: Array(Data(base64Encoded: "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")!)
        )
    
    override func setUp() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: relyingPartyID,
            relyingPartyName: relyingPartyDisplayName,
            relyingPartyOrigin: relyingPartyOrigin
        )
        webAuthnManager = .init(configuration: configuration, challengeGenerator: .mock(generate: challenge))
    }

    func testInvalidVersion() async throws {
        let mockCredentialPublicKey = TestCredentialPublicKeyBuilder().validMockRSA().buildAsByteArray()
        let authData = TestAuthDataBuilder()
            .relyingPartyIDHash(fromRelyingPartyID: relyingPartyID)
            .flags(0b11000101)
            .counter([0b00000000, 0b00000000, 0b00000000, 0b00000000])
            .attestedCredData(credentialPublicKey: mockCredentialPublicKey)
            .noExtensionData()
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.tpm)
            .authData(authData)
            .attStmt(
                .map([.utf8String("ver"): .utf8String("1.0")])
            )
            .build()
            .cborEncoded
        
        await assertThrowsError(
            try await finishRegistration(
                challenge: challenge,
                attestationObject: mockAttestationObject,
                rootCertificatesByFormat: [.tpm: [caCert]]
            ),
            expect: WebAuthnError.tpmInvalidVersion
        )
    }
    
    func testInvalidPubArea() async throws {
        let mockCredentialPublicKey = TestCredentialPublicKeyBuilder().validMockRSA().buildAsByteArray()
        let mockCerts = try TestECCKeyPair.certificates()
        let authData = TestAuthDataBuilder()
            .relyingPartyIDHash(fromRelyingPartyID: relyingPartyID)
            .flags(0b11000101)
            .counter([0b00000000, 0b00000000, 0b00000000, 0b00000000])
            .attestedCredData(credentialPublicKey: mockCredentialPublicKey)
            .noExtensionData()
        let mockAttestationObject = TestAttestationObjectBuilder()
            .fmt(.tpm)
            .authData(authData)
            .attStmt(
                .map([
                    .utf8String("ver"): .utf8String("2.0"),
                    .utf8String("x5c"): .array([.byteString(Array(mockCerts.leaf))]),
                    .utf8String("pubArea"): .byteString([0x01])
                ])
            )
            .build()
            .cborEncoded
        
        await assertThrowsError(
            try await finishRegistration(
                challenge: challenge,
                attestationObject: mockAttestationObject,
                rootCertificatesByFormat: [.tpm: [mockCerts.ca]]
            ),
            expect: WebAuthnError.tpmInvalidPubArea
        )
    }

    func testAttCAAttestationRSASucceeds() async throws {
        let credential = try await finishRegistration(
            challenge: challenge,
            attestationObject: Array(Data(base64Encoded: attestationObjectBase64.urlDecoded.asString())!),
            rootCertificatesByFormat: [.tpm: [caCert]]
        )
        XCTAssertEqual(credential.attestationResult.format, .tpm)
        XCTAssertEqual(credential.attestationResult.type, .attCA)
        XCTAssertEqual(credential.attestationResult.trustChain.count, 3)
    }

    private func finishRegistration(
        challenge: [UInt8],
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
                    clientDataJSON: Array(Data(base64Encoded: clientDataJSONBase64)!),
                    attestationObject: attestationObject
                )
            ),
            requireUserVerification: requireUserVerification,
            rootCertificatesByFormat: rootCertificatesByFormat,
            confirmCredentialIDNotRegisteredYet: confirmCredentialIDNotRegisteredYet
        )
    }
    
}
