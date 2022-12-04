import XCTest

@testable import WebAuthn

final class HelpersTests: XCTestCase {
    func testGenerateChallengeReturnsRandomBytes() throws {
        let webAuthn = WebAuthnManager(
            config: .init(
                relyingPartyDisplayName: "123",
                relyingPartyID: "1",
                relyingPartyOrigin: "http://localhost:8080",
                timeout: 60
            )
        )
        let challenge1 = try webAuthn.generateChallengeString()
        let challenge2 = try webAuthn.generateChallengeString()

        XCTAssertNotEqual(challenge1, challenge2)
    }

    func testBase64URLEncodeReturnsCorrectString() {
        let input: [UInt8] = [1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0]
        let expectedBase64 = "AQABAAEBAAEAAQEAAAABAA=="
        let expectedBase64URL = "AQABAAEBAAEAAQEAAAABAA"

        let base64Encoded = input.base64EncodedString()
        let base64URLEncoded = input.base64URLEncodedString()

        XCTAssertEqual(expectedBase64, base64Encoded)
        XCTAssertEqual(expectedBase64URL, base64URLEncoded)
    }
}
