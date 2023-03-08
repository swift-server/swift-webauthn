import Foundation
import WebAuthn

struct TestClientDataJSON: Encodable {
    var type = "webauthn.create"
    var challenge = "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg"
    var origin = "https://example.com"
    var crossOrigin = false
    var randomOtherKey = "123"

    var base64URLEncoded: URLEncodedBase64 {
        // swiftlint:disable:next force_try
        try! JSONEncoder().encode(self).base64URLEncodedString()
    }
}
