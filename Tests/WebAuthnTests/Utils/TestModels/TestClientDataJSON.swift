import Foundation
import WebAuthn

struct TestClientDataJSON: Encodable {
    var type = "webauthn.create"
    var challenge = TestConstants.mockChallenge
    var origin = "https://example.com"
    var crossOrigin = false
    var randomOtherKey = "123"

    var base64URLEncoded: URLEncodedBase64 {
        jsonData.base64URLEncodedString()
    }

    var jsonData: Data {
        // swiftlint:disable:next force_try
        try! JSONEncoder().encode(self)
    }
}
