//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import Logging

/// Container for base64 encoded data
public struct EncodedBase64: ExpressibleByStringLiteral, Codable, Hashable, Equatable, Sendable {
    private let base64: String

    public init(_ string: String) {
        self.base64 = string
    }

    public init(stringLiteral value: StringLiteralType) {
        self.init(value)
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.base64 = try container.decode(String.self)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.base64)
    }

    /// Return as Base64URL
    public var urlEncoded: URLEncodedBase64 {
        return .init(
            self.base64.replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        )
    }

    /// Decodes Base64 string and transforms result into `Data`
    public var decoded: Data? {
        return Data(base64Encoded: self.base64)
    }

    /// Returns Base64 data as a String
    public func asString() -> String {
        return self.base64
    }
}

/// Container for URL encoded base64 data
public struct URLEncodedBase64: ExpressibleByStringLiteral, Codable, Hashable, Equatable, Sendable {
    let base64URL: String

    /// Decodes Base64URL string and transforms result into `[UInt8]`
    public var decodedBytes: [UInt8]? {
        guard let base64DecodedData = urlDecoded.decoded else { return nil }
        return [UInt8](base64DecodedData)
    }

    public init(_ string: String) {
        self.base64URL = string
    }

    public init(stringLiteral value: StringLiteralType) {
        self.init(value)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.base64URL = try container.decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.base64URL)
    }

    /// Decodes Base64URL into Base64
    public var urlDecoded: EncodedBase64 {
        var result = self.base64URL.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while result.count % 4 != 0 {
            result = result.appending("=")
        }
        return .init(result)
    }

    /// Return Base64URL as a String
    public func asString() -> String {
        return self.base64URL
    }
}

extension Array where Element == UInt8 {
    /// Encodes an array of bytes into a base64url-encoded string
    /// - Returns: A base64url-encoded string
    public func base64URLEncodedString() -> URLEncodedBase64 {
        let base64String = Data(bytes: self, count: self.count).base64EncodedString()
        return EncodedBase64(base64String).urlEncoded
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
    func toBase64() -> EncodedBase64 {
        return .init(Data(self.utf8).base64EncodedString())
    }
}
