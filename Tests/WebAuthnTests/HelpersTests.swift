import XCTest

@testable import WebAuthn

final class HelpersTests: XCTestCase {
    func testBase64URLEncodeReturnsCorrectString() {
        let input: [UInt8] = [1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0]
        let expectedBase64 = "AQABAAEBAAEAAQEAAAABAA=="
        let expectedBase64URL = "AQABAAEBAAEAAQEAAAABAA"

        let base64Encoded = input.base64EncodedString()
        let base64URLEncoded = input.base64URLEncodedString()

        XCTAssertEqual(expectedBase64, base64Encoded.string)
        XCTAssertEqual(expectedBase64URL, base64URLEncoded.string)
    }

    func testEncodeBase64Codable() throws {
        let base64 = EncodedBase64("AQABAAEBAAEAAQEAAAABAA==")
        let json = try JSONEncoder().encode(base64)
        let decodedBase64 = try JSONDecoder().decode(EncodedBase64.self, from: json)
        XCTAssertEqual(base64, decodedBase64)
    }
}
