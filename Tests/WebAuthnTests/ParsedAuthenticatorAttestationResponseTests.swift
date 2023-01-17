import XCTest
import SwiftCBOR
@testable import WebAuthn

// swiftlint:disable line_length

// swiftlint:disable:next type_name
final class ParsedAuthenticatorAttestationResponseTests: XCTestCase {
    let realClientDataJSON = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"
    let realAttestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIDo-5W3Kur7A7y9Lfw7ijhExfCz3_5coMEQNY_y6p-JrpQECAyYgASFYIJr_yLoYbYWgcf7aQcd7pcjUj-3o8biafWQH28WijQSvIlggPI2KqqRQ26KKuFaJ0yH7nouCBrzHu8qRONW-CPa9VDM"

    func testInitFromRawResponseFailsWithInvalidClientDataJSON() throws {
        XCTAssertThrowsError(try parseResponse(
            clientDataJSON: "a", // this isn't base64 decodable, so parsing should fail
            attestationObject: ""
        )) { error in
            XCTAssertEqual(error as? WebAuthnError, .invalidClientDataJSON)
        }
    }

    func testInitFromRawResponseFailsIfClientDataJSONDecodingFails() throws {
        XCTAssertThrowsError(try parseResponse(
            clientDataJSON: "abc", // this is base64 decodable, but will not result in a proper clientData json object
            attestationObject: ""
        )) { error in
            XCTAssertNotNil(error as? DecodingError)
        }
    }

    func testInitFromRawResponseFailsIfAttestationObjectIsNotBase64() throws {
        XCTAssertThrowsError(try parseResponse(
            clientDataJSON: realClientDataJSON,
            attestationObject: "a"
        )) { error in
            XCTAssertEqual(error as? WebAuthnError, .invalidAttestationObject)
        }
    }

    func testInitFromRawResponseFailsIfAuthDataIsInvalid() throws {
        let attestationObjectWithInvalidAuthData = "A363666D74667061636B65646761747453746D74A263616C67266373696758473045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C68617574684461746101"
        XCTAssertThrowsError(try parseResponse(
            clientDataJSON: realClientDataJSON,
            attestationObject: attestationObjectWithInvalidAuthData
        )) { error in
            XCTAssertEqual(error as? WebAuthnError, .invalidAuthData)
        }
    }

    func testInitFromRawResponseFailsIfFmtIsInvalid() throws {
        let attestationObjectWithInvalidFmt = "o2NmbXQBZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIDo-5W3Kur7A7y9Lfw7ijhExfCz3_5coMEQNY_y6p-JrpQECAyYgASFYIJr_yLoYbYWgcf7aQcd7pcjUj-3o8biafWQH28WijQSvIlggPI2KqqRQ26KKuFaJ0yH7nouCBrzHu8qRONW-CPa9VDM"
        XCTAssertThrowsError(try parseResponse(
            clientDataJSON: realClientDataJSON,
            attestationObject: attestationObjectWithInvalidFmt
        )) { error in
            XCTAssertEqual(error as? WebAuthnError, .invalidFmt)
        }
    }

    func testInitFromRawResponseFailsIfAttStmtIsMissing() throws {
        let attestationObjectWithMissingAttStmt = "omNmbXRmcGFja2VkaGF1dGhEYXRhWKRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAAArc4AAjW8xgpkiwsl8fBVAwAgOj7lbcq6vsDvL0t_DuKOETF8LPf_lygwRA1j_Lqn4mulAQIDJiABIVggmv_IuhhthaBx_tpBx3ulyNSP7ejxuJp9ZAfbxaKNBK8iWCA8jYqqpFDbooq4VonTIfuei4IGvMe7ypE41b4I9r1UMw"
        XCTAssertThrowsError(try parseResponse(
            clientDataJSON: realClientDataJSON,
            attestationObject: attestationObjectWithMissingAttStmt
        )) { error in
            XCTAssertEqual(error as? WebAuthnError, .missingAttStmt)
        }
    }

    func testInitFromRawResponseSucceeds() throws {
        let expectedAttestationObject = AttestationObject(
            authenticatorData: AuthenticatorData(
                relyingPartyIDHash: "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763".hexadecimal!,
                flags: AuthenticatorFlags(
                    userPresent: true,
                    userVerified: true,
                    isBackupEligible: false,
                    isCurrentlyBackedUp: false,
                    attestedCredentialData: true,
                    extensionDataIncluded: false
                ),
                counter: 0,
                attestedData: AttestedCredentialData(
                    aaguid: "adce000235bcc60a648b0b25f1f05503".hexadecimal!,
                    credentialID: "3a3ee56dcababec0ef2f4b7f0ee28e11317c2cf7ff972830440d63fcbaa7e26b".hexadecimal!,
                    publicKey: "a50102032620012158209affc8ba186d85a071feda41c77ba5c8d48fede8f1b89a7d6407dbc5a28d04af2258203c8d8aaaa450dba28ab85689d321fb9e8b8206bcc7bbca9138d5be08f6bd5433".hexadecimal!
                ),
                extData: nil
            ),
            rawAuthenticatorData: "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634500000000adce000235bcc60a648b0b25f1f0550300203a3ee56dcababec0ef2f4b7f0ee28e11317c2cf7ff972830440d63fcbaa7e26ba50102032620012158209affc8ba186d85a071feda41c77ba5c8d48fede8f1b89a7d6407dbc5a28d04af2258203c8d8aaaa450dba28ab85689d321fb9e8b8206bcc7bbca9138d5be08f6bd5433".hexadecimal!,
            format: .packed,
            attestationStatement: .map([
                .utf8String("sig"): .byteString("3045022035346DA48FD238E655CD4D6937FE1C5FEA2CA943E21CC396E3CAAAABDD435DF5022100BE30789A231B7639D23182A627C940C771E7AF34E31F3E26DE9DA6D01AF5E08C".hexadecimal!),
                .utf8String("alg"): .negativeInt(6)
            ])
        )

        let response = try parseResponse(clientDataJSON: realClientDataJSON, attestationObject: realAttestationObject)

        XCTAssertEqual(response.clientData.challenge, "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg")
        XCTAssertEqual(response.clientData.origin, "http://localhost:8080")
        XCTAssertEqual(response.clientData.type, .create)

        XCTAssertEqual(expectedAttestationObject, response.attestationObject)
    }

    private func parseResponse(
        clientDataJSON: URLEncodedBase64,
        attestationObject: URLEncodedBase64
    ) throws
    -> ParsedAuthenticatorAttestationResponse {
        try ParsedAuthenticatorAttestationResponse(from: .init(
            clientDataJSON: clientDataJSON,
            attestationObject: attestationObject
        ))
    }
}
