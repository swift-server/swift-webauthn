import XCTest
@testable import WebAuthn

final class ParsedCredentialCreationResponseTests: XCTestCase {
    func testParsingSucceeds() throws {
        // swiftlint:disable line_length
        let response = RegistrationCredential(
            id: "Oj7lbcq6vsDvL0t_DuKOETF8LPf_lygwRA1j_Lqn4ms",
            type: "public-key",
            rawID: "Oj7lbcq6vsDvL0t_DuKOETF8LPf_lygwRA1j_Lqn4ms",
            attestationResponse: AuthenticatorAttestationResponse(
                clientDataJSON: "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0",
                attestationObject: "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIDo-5W3Kur7A7y9Lfw7ijhExfCz3_5coMEQNY_y6p-JrpQECAyYgASFYIJr_yLoYbYWgcf7aQcd7pcjUj-3o8biafWQH28WijQSvIlggPI2KqqRQ26KKuFaJ0yH7nouCBrzHu8qRONW-CPa9VDM"
            )
        )

        let parsedResponse = try ParsedCredentialCreationResponse(from: response)

        print(parsedResponse)

        let expectedRawID: [UInt8] = [58, 62, 229, 109, 202, 186, 190, 192, 239, 47, 75, 127, 14, 226, 142, 17, 49, 124, 44, 247, 255, 151, 40, 48, 68, 13, 99, 252, 186, 167, 226, 107]
        // let expectedResponse = ParsedAuthenticatorAttestationResponse(clientData: .init, attestationObject: .init(clientDataJSON: URLEncodedBase64, attestationObject: String))

        XCTAssertEqual(parsedResponse.id, "Oj7lbcq6vsDvL0t_DuKOETF8LPf_lygwRA1j_Lqn4ms")
        XCTAssertEqual(parsedResponse.type, "public-key")
        XCTAssertEqual(parsedResponse.rawID, Data(bytes: expectedRawID, count: expectedRawID.count))
        // XCTAssertEqual(parsedResponse.response, nil)

        // swiftlint:enable line_length
    }
}
