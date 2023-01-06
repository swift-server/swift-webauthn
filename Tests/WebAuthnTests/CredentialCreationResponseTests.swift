import XCTest
@testable import WebAuthn

final class RegistrationResponseTests: XCTestCase {
    func testDecodingFromJSONSucceeds() throws {
        // swiftlint:disable line_length
        let json = """
        {"id":"Oj7lbcq6vsDvL0t_DuKOETF8LPf_lygwRA1j_Lqn4ms","rawId":"Oj7lbcq6vsDvL0t_DuKOETF8LPf_lygwRA1j_Lqn4ms","type":"public-key","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIDo-5W3Kur7A7y9Lfw7ijhExfCz3_5coMEQNY_y6p-JrpQECAyYgASFYIJr_yLoYbYWgcf7aQcd7pcjUj-3o8biafWQH28WijQSvIlggPI2KqqRQ26KKuFaJ0yH7nouCBrzHu8qRONW-CPa9VDM","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"}}
        """

        let response = try JSONDecoder().decode(RegistrationResponse.self, from: json.data(using: .utf8)!)

        XCTAssertEqual(response.id, "Oj7lbcq6vsDvL0t_DuKOETF8LPf_lygwRA1j_Lqn4ms")
        XCTAssertEqual(response.rawID, "Oj7lbcq6vsDvL0t_DuKOETF8LPf_lygwRA1j_Lqn4ms")
        XCTAssertEqual(response.type, "public-key")
        XCTAssertEqual(
            response.attestationResponse.clientDataJSON,
            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"
        )
        XCTAssertEqual(
            response.attestationResponse.attestationObject,
            "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIDo-5W3Kur7A7y9Lfw7ijhExfCz3_5coMEQNY_y6p-JrpQECAyYgASFYIJr_yLoYbYWgcf7aQcd7pcjUj-3o8biafWQH28WijQSvIlggPI2KqqRQ26KKuFaJ0yH7nouCBrzHu8qRONW-CPa9VDM"
        )
        // swiftlint:enable line_length
    }
}
