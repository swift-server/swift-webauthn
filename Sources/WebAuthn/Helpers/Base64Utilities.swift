import Foundation
import Logging

extension Array where Element == UInt8 {
    /// Encodes an array of bytes into a base64url-encoded string
    /// - Returns: A base64url-encoded string
    public func base64URLEncodedString() -> String {
        let base64String = Data(bytes: self, count: self.count).base64EncodedString()
        return base64String.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Encodes an array of bytes into a base64 string
    /// - Returns: A base64-encoded string
    public func base64EncodedString() -> String {
        return Data(bytes: self, count: self.count).base64EncodedString()
    }
}

extension String {
    /// Decode a base64url-encoded `String` to a base64 `String`
    /// - Returns: A base64-encoded `String`
    public static func base64(fromBase64URLEncoded base64URLEncoded: String) -> Self {
        return base64URLEncoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    }
}

extension String {
    var base64URLDecodedData: Data? {
        var result = self.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while result.count % 4 != 0 {
            result = result.appending("=")
        }
        return Data(base64Encoded: result)
    }
}