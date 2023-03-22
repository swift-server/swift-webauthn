import WebAuthn

struct TestConstants {
    static var mockChallenge: URLEncodedBase64 = "cmFuZG9tU3RyaW5nRnJvbVNlcnZlcg"
    static var mockCredentialID: URLEncodedBase64 = [0, 1, 2, 3, 4].base64URLEncodedString()
}
