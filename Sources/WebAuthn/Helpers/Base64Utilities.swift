//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2022 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import Logging

/// Container for URL encoded base64 data
public struct URLEncodedBase64: ExpressibleByStringLiteral, Codable, Hashable {
    let string: String

    public init(_ string: String) {
        self.string = string
    }

    public init(stringLiteral value: StringLiteralType) {
        self.init(value)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.string = try container.decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.string)
    }
}

/// Container for base64 encoded data
public struct EncodedBase64: ExpressibleByStringLiteral, Codable, Hashable {
    let string: String

    public init(_ string: String) {
        self.string = string
    }

    public init(stringLiteral value: StringLiteralType) {
        self.init(value)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.string = try container.decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.string)
    }
}

//public typealias URLEncodedBase64 = String
//public typealias EncodedBase64 = String

extension Array where Element == UInt8 {
    /// Encodes an array of bytes into a base64url-encoded string
    /// - Returns: A base64url-encoded string
    public func base64URLEncodedString() -> URLEncodedBase64 {
        let base64String = Data(bytes: self, count: self.count).base64EncodedString()
        return String.base64URL(fromBase64: .init(base64String))
    }

    /// Encodes an array of bytes into a base64 string
    /// - Returns: A base64-encoded string
    public func base64EncodedString() -> EncodedBase64 {
        return .init(Data(bytes: self, count: self.count).base64EncodedString())
    }
}

extension Data {
    /// Encodes data into a base64url-encoded string
    /// - Returns: A base64url-encoded string
    public func base64URLEncodedString() -> URLEncodedBase64 {
        return [UInt8](self).base64URLEncodedString()
    }
}

extension String {
    /// Decode a base64url-encoded `String` to a base64 `String`
    /// - Returns: A base64-encoded `String`
    public static func base64(fromBase64URLEncoded base64URLEncoded: URLEncodedBase64) -> EncodedBase64 {
        return .init(
            base64URLEncoded.string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        )
    }

    public static func base64URL(fromBase64 base64Encoded: EncodedBase64) -> URLEncodedBase64 {
        return .init(
            base64Encoded.string.replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        )
    }

    func toBase64() -> EncodedBase64 {
        return .init(Data(self.utf8).base64EncodedString())
    }
}

extension URLEncodedBase64 {
    public var base64URLDecodedData: Data? {
        var result = self.string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while result.count % 4 != 0 {
            result = result.appending("=")
        }
        return Data(base64Encoded: result)
    }
}
