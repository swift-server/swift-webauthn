import XCTest
@testable import WebAuthn

final class HelpersTests: XCTestCase {
    func testGenerateChallengeReturnsRandomBytes() throws {
        let webAuthn = WebAuthnManager(config: .init(relyingPartyDisplayName: "123", relyingPartyID: "1", timeout: 60))
        let challenge1 = try webAuthn.generateChallenge()
        let challenge2 = try webAuthn.generateChallenge()

        XCTAssertNotEqual(challenge1, challenge2)
    }

    func testBase64URLEncodeReturnsCorrectString() {
        let input: [UInt8] = [1, 0, 1, 0, 1, 1]
        let expectedBase64 = Data(bytes: input, count: input.count).base64EncodedString()

        let base64URLEncoded = input.base64URLEncodedString()
        let base64Encoded = base64URLEncoded.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        XCTAssertEqual(expectedBase64, base64Encoded)
    }
}