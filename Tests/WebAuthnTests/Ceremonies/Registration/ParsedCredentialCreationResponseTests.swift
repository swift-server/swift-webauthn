import XCTest
@testable import WebAuthn

// swiftlint:disable line_length

final class ParsedCredentialCreationResponseTests: XCTestCase {
    func testInitFromRawResponseFailsWithInvalidRawID() throws {
        let registrationCredential = createRegistrationCredential(rawID: "%")

        XCTAssertThrowsError(try ParsedCredentialCreationResponse(from: registrationCredential)) { error in
            XCTAssertEqual(error as? WebAuthnError, .invalidRawID)
        }
    }

    func testInitFromRawResponseFailsWithInvalidType() throws {
        let registrationCredential = createRegistrationCredential(type: "some invalid type")

        XCTAssertThrowsError(try ParsedCredentialCreationResponse(from: registrationCredential)) { error in
            XCTAssertEqual(error as? WebAuthnError, .invalidCredentialCreationType)
        }
    }

    func testInitFromRawResponseSucceeds() throws {
        let registrationCredential = createRegistrationCredential()
        XCTAssertNoThrow(try ParsedCredentialCreationResponse(from: registrationCredential))
    }

    private func createRegistrationCredential(
        id: String = "123",
        type: String = "public-key",
        rawID: String = "123",
        clientDataJSON: String = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0",
        attestationObject: String = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgNTRtpI_SOOZVzU1pN_4cX-osqUPiHMOW48qqq91DXfUCIQC-MHiaIxt2OdIxgqYnyUDHceevNOMfPibenabQGvXgjGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIDo-5W3Kur7A7y9Lfw7ijhExfCz3_5coMEQNY_y6p-JrpQECAyYgASFYIJr_yLoYbYWgcf7aQcd7pcjUj-3o8biafWQH28WijQSvIlggPI2KqqRQ26KKuFaJ0yH7nouCBrzHu8qRONW-CPa9VDM"
    ) -> RegistrationCredential {
        RegistrationCredential(
            id: id,
            type: type,
            rawID: rawID,
            attestationResponse: .init(clientDataJSON: clientDataJSON, attestationObject: attestationObject)
        )
    }
}
