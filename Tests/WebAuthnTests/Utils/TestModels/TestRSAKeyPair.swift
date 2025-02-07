//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2023 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import Crypto
import WebAuthn
import _CryptoExtras

struct TestRSAKeyPair: TestSigner {
    static let privateKeyPEM = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpQIBAAKCAQEAngCfNRz1D1HvyvWxURSKpGtymY/qUOW0JfQ77jc8S6p1D/78
    w886pOdcPkfWQbR/qN7PbwfVDHFSJW1wbMSVdwwcUa9ELMpgQIqkLoBEjohWyAT2
    PGKfpEskSTZfq0K/CZ+ZZ4YwNNt/IH7mZhKGQHS5SHpgRAXJuATxQmt4vFSwBp+8
    aN4Wmbzl+S3w2vLY2JaEPT3rL0t5WNQa2QLhH4JWBpSywe0Jl1LxWj+gOZJdZJeN
    c1dZtvwnhHXrwg0EjLILFf8V3GglWj8Gg6xuPo8+IQi+gjQEnDiOJpm7uhK4h7qZ
    iK2FzUlu4PYm/4oha+LvK7IKcjjFgyAuwq6sKQIDAQABAoIBAEoE5JDPRgatTfb4
    7t6bDvBD3eYOw6iuU5zMNB8/BSI1cq3RuLxKoqCKOm563ObfFkcYSnkrZCV2GROr
    l1V9KsAgjku+HeQV0s2ppYybToKvYGhH2ssjMMKY6SDbNipXFIP/nrAe7wp0IbQp
    fuoml3outHY9zkdPptZsilGhY2hmT6oAcoOt2ZWj8mITiQgxGzbT5vQBjkyppFMm
    k5h+C64nS6EiJuJUUDUbvkD5hE+nHFr+165oPUmPCXGYGBiayGh8j9j7AHfGAdH3
    zSW+PWDMX9vApJZZauQ4FA7FDXzzFjiT3Xcqyl+yyqL/D5YA+GsSE3pbPZJcLJi2
    ZQ0ShbkCgYEAzhItmWbRILbXULoDfqSXYxW2XXt6Z0JFy3AaOfhbAHYUazraqByY
    l0AKVMVp5cH9qk2Z/s/oqIcfsBa3P8H73yBRrDJuPQpcTWuT71qjGfgqQABqzInc
    71IB2F6WZ2Dnkh1uPczS+wiy8kv7Z4nM3hJhvgJ/ZGInQffYNSoiQisCgYEAxEjt
    gTZPwXn9PyVmwW19CN1ZNR22nzTqMDZQZMvDYCbLcMEJ+Ls3TvVX5IA5hrGWGa6v
    n18CdvAWebmLBww7w0FX2KF4Ug0+YGEOH15wg352dtBQ1Jx8fqeX+z+OoCjNVdiH
    YDpTXd7xjcs2umotisH+vo6NHnQLuBnOcGc9ZPsCgYEAiiMtZhPCRIfMtlS7Wv3C
    ba10Xh4T43xNhR5Utl+BwUFmVqtRQDhLIbjQNBtR7a6o+KykemessqxB1aykkpza
    1qu3lBMKSujTDyL6PA0qIJJ24Ahnj00rSVJT4lMlx47yLMSFze+rzpP6QOomUTXS
    m1r/InxSIVyarGIUES95X5kCgYEAvnct0FZNaibfsSiv3z5JOBLh/4LHtRF5tjLe
    LBD1kxXSD6Wh8XRppPq5wQcTyzoDtwQlcvaUw6kRhiifWcVrMHr1rUZyJNypDIjh
    VVskvtQ2S/C0nrsCqzwhZDI2Sf+N0KF+K8gtIUe3CaqJfraNXroEYhCdq1FcFdck
    1Tm4/4UCgYEAj+raCSTOBazoE8Z+53WUJ8Y/ZrbqEc7y7ltl6FgbZLWArETglNCD
    FmTawde5HZJza2x+BUJpy+31ChbaIctdu6O2tZZCa2FwdtAXf86ZJe0By4fhmK9v
    m0Eq9qinAmFyVbkuIzqCJMGeC1FxUYIf/DkpAMOb/ACTyig+YFgFjdU=
    -----END RSA PRIVATE KEY-----
    """

    static let publicKeyPEM = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAngCfNRz1D1HvyvWxURSK
    pGtymY/qUOW0JfQ77jc8S6p1D/78w886pOdcPkfWQbR/qN7PbwfVDHFSJW1wbMSV
    dwwcUa9ELMpgQIqkLoBEjohWyAT2PGKfpEskSTZfq0K/CZ+ZZ4YwNNt/IH7mZhKG
    QHS5SHpgRAXJuATxQmt4vFSwBp+8aN4Wmbzl+S3w2vLY2JaEPT3rL0t5WNQa2QLh
    H4JWBpSywe0Jl1LxWj+gOZJdZJeNc1dZtvwnhHXrwg0EjLILFf8V3GglWj8Gg6xu
    Po8+IQi+gjQEnDiOJpm7uhK4h7qZiK2FzUlu4PYm/4oha+LvK7IKcjjFgyAuwq6s
    KQIDAQAB
    -----END PUBLIC KEY-----
    """
    static let publicKeyNCoordinate = [UInt8](try! _RSA.Signing.PublicKey(pemRepresentation: publicKeyPEM).getKeyPrimitives().modulus)
    static let publicKeyECoordinate = [UInt8](try! _RSA.Signing.PublicKey(pemRepresentation: publicKeyPEM).getKeyPrimitives().publicExponent)

    static func sign(data: Data) throws -> [UInt8] {
        let privateKey = try _RSA.Signing.PrivateKey(pemRepresentation: privateKeyPEM)
        return Array(try privateKey.signature(for: data,padding:_RSA.Signing.Padding.insecurePKCS1v1_5).rawRepresentation)
    }

    static var signature: [UInt8] {
        get throws {
            let authenticatorData = TestAuthDataBuilder()
                .validAuthenticationMock()
                .buildAsBase64URLEncoded()

            // Create a signature. This part is usually performed by the authenticator
            let clientData: Data = TestClientDataJSON(type: "webauthn.get").jsonData
            let clientDataHash = SHA256.hash(data: clientData)
            let rawAuthenticatorData = authenticatorData.urlDecoded.decoded!
            let signatureBase = rawAuthenticatorData + clientDataHash

            return try sign(data: signatureBase)
        }
    }
}

extension TestKeyConfiguration {
    static let rsa = TestKeyConfiguration(
        signer: TestRSAKeyPair.self,
        credentialPublicKeyBuilder: TestCredentialPublicKeyBuilder().validMockRSA(),
        authDataBuilder: TestAuthDataBuilder().validMockRSA(),
        attestationObjectBuilder: TestAttestationObjectBuilder().validMockRSA()
    )
}
