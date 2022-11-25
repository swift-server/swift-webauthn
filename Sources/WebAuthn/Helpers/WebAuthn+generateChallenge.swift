import Foundation
import Logging

extension WebAuthn {
    struct ChallengeGeneratorError: Error {}
    /// Generate a suitably random value to be used as an attestation or assertion challenge
    /// - Throws: An error if something went wrong while generating random byte
    /// - Returns: 32 bytes
    public static func generateChallenge() throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw ChallengeGeneratorError() }
        return bytes
    }
}

extension Array where Element == UInt8 {
    /// Encodes an array of bytes into a base64url-encoded string
    /// - Returns: A base64url-encoded string
    public func base64URLEncode() -> String {
        let base64String = Data(bytes: self, count: self.count).base64EncodedString()
        return base64String.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension String {
    /// Decode a base64url-encoded `String` to a base64 `String`
    /// - Returns: A base64-encoded `String`
    public static func base64(fromBase64URLEncoded base64URLEncoded: String) -> Self {
        return base64URLEncoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    }
}