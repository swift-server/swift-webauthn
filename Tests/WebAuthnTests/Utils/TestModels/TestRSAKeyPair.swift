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

import Foundation
import Crypto
import _CryptoExtras
import WebAuthn
import X509
import SwiftASN1

struct TestRSAKeyPair {
    static let privateKeyPEM = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA2VnofJn24NHyyGDU4tV1rGsuiI9FBSR7KKU7vkvxqA3GIWO1
    3Wx8J3Nmcf+U/SXdgs+z9HdiHblvsMQSQxTwLyXxHCB6bYSSOLC+2nHGVxQqDEc2
    LwZ3gQnaGhwLuHCrffdB6tTCrblDDuCb3agMyRMFz8R0kOiu9+GGj0tLspA62uLx
    etPSFNsjqdxK5YZEWnGULz/MNgqTR4LUVRaUM6F6o3JVi6UKy4dlXHEpxjTLr7y3
    1W4AbQVC5M5FElwxMYmTAQrodhtRyGwqdzMxrWjxA7RckBGmMjXhk4ls0v0IAvyB
    RUCR1zw3c6Swk2q5Sy1itNC0Y62d1Ru2jdLhxQIDAQABAoIBAAgmB8JMH2ZUWK7M
    eo66g/vf1NHH1UWZFYjzkObUgA3V3ly4GURg4dK0z91sQJCxD7nswYljxGjq39YX
    s7uSGGMcIAr26MAcXUME1VLpOw9esSjerphavLY4wVWDQak7iCJj17PPIDFVJb90
    CkPoHfqX3PrqGZipMI4YhWvv3bmm/uzvdMvNB1bWmYLg/zCYATPugZ+XthqiLGDI
    lohsrN2S06uJYBc+nEGI8PU2OST00PK/qemhR/SNRfukaqzJbkEC23lG1s3U7pgj
    ucLxb2Ss4I6naJboUFybTAGp/yJf4FYaThiW9v9KDfPpvilj2LNhnVFTNflevMVG
    bQXktwECgYEA8QJ/Y/BBIGSrlbco16jFXelR4kpG6z5xZ2MQP1i8ktE/9N47TtlP
    S4cU+JH0X1bx0516IUw0ib2+IH6ogl7AWM4tjEPzVeLwHds9sgtKZS8ZO/MwFlkl
    TVYBrx6sTaF2OV/6TAlFfNzVmpPeXfn4E0GzLG+FM2cxSxwOOS7kLwUCgYEA5t60
    bxclfHW9iCrpahxvBr+BrozKcNIPbaRfe1pqVVZTo71lU4aa+5RXffd6xiTfXw73
    ZYj+82uHeChslACYgcIppqjYodI7hEBLIi9ab/WVSIuSNe16VTjDFbQbqHrgcUhm
    G4KDMyrYQtsDecMFB27SzoBrxbFJ+9NJ49zS48ECgYEA0vQwtTVSjBwR5FYRtdLQ
    DsdvGPeS484gTTJ0wj3VsVze8mKi3v1vXti6DmkS0XC081lf0U12nyoqBR9YN+Tf
    z9uIGsJPd9nP+xIwCmu/jpmPKN5QNP+KmwqxJqtefgTaCpZr66oh3I0fmtHbTb7C
    2XgkcLychsXIa8n+2SamLFECgYA13qlDcqcwj1iWOU0VkWTmsjDURc3G3Xz0HHKb
    GdHN78K8ZikKgFIRed+gaOqg6WGlkJxxeLHkoqaNhwEu16S+Qkvts2A5AhEZHtdp
    NptnnGok70xCgRMWZ5Q9sDTz7xgH1tjcemuauNiVYP1CoBrATT+rJ5P+IQweUoLf
    RFuBAQKBgCD7w9XOEvCuZNvMM+LtaxUQI5hProiVo8cke/rvu/cxM5EOTOXZGyzW
    E7gerNu2WpoRLty1ps6XkwLUTcQ8UblceuYtqa2URFKig0HJRuIw5iqSxrlpVjfZ
    Y2dC2Bo/X4j0M0bKwt/IbGFKNuyTKAtCDgQPUfmzHFhWKAb1Pd4R
    -----END RSA PRIVATE KEY-----
    """

    static let publicKeyPEM = """
    -----BEGIN RSA PUBLIC KEY-----
    MIIBCgKCAQEA2VnofJn24NHyyGDU4tV1rGsuiI9FBSR7KKU7vkvxqA3GIWO13Wx8
    J3Nmcf+U/SXdgs+z9HdiHblvsMQSQxTwLyXxHCB6bYSSOLC+2nHGVxQqDEc2LwZ3
    gQnaGhwLuHCrffdB6tTCrblDDuCb3agMyRMFz8R0kOiu9+GGj0tLspA62uLxetPS
    FNsjqdxK5YZEWnGULz/MNgqTR4LUVRaUM6F6o3JVi6UKy4dlXHEpxjTLr7y31W4A
    bQVC5M5FElwxMYmTAQrodhtRyGwqdzMxrWjxA7RckBGmMjXhk4ls0v0IAvyBRUCR
    1zw3c6Swk2q5Sy1itNC0Y62d1Ru2jdLhxQIDAQAB
    -----END RSA PUBLIC KEY-----
    """
    
    static let publicKeyExponent = withUnsafeBytes(of: UInt32(65537).bigEndian, Array.init)
    static let publicKeyModulus = "d959e87c99f6e0d1f2c860d4e2d575ac6b2e888f4505247b28a53bbe4bf1a80dc62163b5dd6c7c27736671ff94fd25dd82cfb3f477621db96fb0c4124314f02f25f11c207a6d849238b0beda71c657142a0c47362f06778109da1a1c0bb870ab7df741ead4c2adb9430ee09bdda80cc91305cfc47490e8aef7e1868f4b4bb2903adae2f17ad3d214db23a9dc4ae586445a71942f3fcc360a934782d455169433a17aa372558ba50acb87655c7129c634cbafbcb7d56e006d0542e4ce45125c31318993010ae8761b51c86c2a773331ad68f103b45c9011a63235e193896cd2fd0802fc81454091d73c3773a4b0936ab94b2d62b4d0b463ad9dd51bb68dd2e1c5".hexadecimal!

    static func signature(data: Data) throws -> _RSA.Signing.RSASignature {
        let privateKey = try _RSA.Signing.PrivateKey(pemRepresentation: privateKeyPEM)
        return try privateKey.signature(for: data, padding: .insecurePKCS1v1_5)
    }

    static var signature: [UInt8] {
        let authenticatorData = TestAuthDataBuilder()
            .validAuthenticationMock()
            .buildAsBase64URLEncoded()

        // Create a signature. This part is usually performed by the authenticator
        let clientData: Data = TestClientDataJSON(type: "webauthn.get").jsonData
        let clientDataHash = SHA256.hash(data: clientData)
        let rawAuthenticatorData = authenticatorData.urlDecoded.decoded!
        let signatureBase = rawAuthenticatorData + clientDataHash
        // swiftlint:disable:next force_try
        let signature = try! TestRSAKeyPair.signature(data: signatureBase).rawRepresentation

        return [UInt8](signature)
    }
    
    static func certificates() throws -> (leaf: Data, ca: Certificate) {
        let caPrivateKey = try _RSA.Encryption.PrivateKey.init(keySize: .bits2048)
        let ca = try Certificate.init(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(pemEncoded: caPrivateKey.publicKey.pemRepresentation),
            notValidBefore: Date(),
            notValidAfter: Date().advanced(by: 3600),
            issuer: DistinguishedName { CommonName("Example CA") },
            subject: DistinguishedName { CommonName("Example CA") },
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try .init{
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 1))
            },
            issuerPrivateKey: .init(pemEncoded: caPrivateKey.pemRepresentation)
        )
        
        let privateKey = try _RSA.Encryption.PrivateKey(pemRepresentation: privateKeyPEM)
        let leaf = try Certificate.init(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(pemEncoded: privateKey.publicKey.pemRepresentation),
            notValidBefore: Date(),
            notValidAfter: Date().advanced(by: 3600),
            issuer: ca.subject,
            subject: DistinguishedName {
                CommonName("Example leaf certificate")
                OrganizationalUnitName("Authenticator Attestation")
                OrganizationName("Example vendor")
                CountryName("US")
            },
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try Certificate.Extensions {Critical(BasicConstraints.notCertificateAuthority)},
            issuerPrivateKey: .init(pemEncoded: caPrivateKey.pemRepresentation)
        )
        var leafSerializer = DER.Serializer()
        try leafSerializer.serialize(leaf)
        let leafDER = leafSerializer.serializedBytes
        
        return (leaf: Data(leafDER), ca: ca)
    }
}
