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

/// Container for base64 encoded data
public struct EncodedBase64: Codable, Hashable, Equatable, ExpressibleByStringLiteral {
    
    public let value: String
    
    public init(value: String) {
        self.value = value
    }

    public init(stringLiteral value: StringLiteralType) {
        self.init(value: value)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(String.self)
        self.init(value: value)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.value)
    }
    
    var urlEncoded: URLEncodedBase64 {
        URLEncodedBase64(base64: self)
    }

    /// Decodes Base64 string and transforms result into `[UInt8]`
    public var decodedBytes: [UInt8]? {
        guard let data = Data(base64Encoded: self.value) else {
            return nil
        }
        return [UInt8](data)
    }
}

/// Container for URL encoded base64 data
public struct URLEncodedBase64: Codable, Hashable, Equatable, ExpressibleByStringLiteral {
    
    public let value: String
    
    public init(value: String) {
        self.value = value
    }
    
    public init(stringLiteral value: StringLiteralType) {
        self.init(value: value)
    }

    /// Decodes Base64URL string and transforms result into `[UInt8]`
    public var decodedBytes: [UInt8]? {
        urlDecoded.decodedBytes
    }

    public init(base64: EncodedBase64) {
        let value = base64.value
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        self.init(value: value)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(String.self)
        self.init(value: value)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.value)
    }

    /// Decodes Base64URL into Base64
    public var urlDecoded: EncodedBase64 {
        var value = self.value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while value.count % 4 != 0 {
            value = value.appending("=")
        }
        return .init(value: value)
    }
}

extension Array where Element == UInt8 {
    /// Encodes an array of bytes into a base64url-encoded string
    /// - Returns: A base64url-encoded string
    public func base64URLEncoded() -> URLEncodedBase64 {
        let base64String = Data(bytes: self, count: self.count).base64EncodedString()
        return EncodedBase64(value: base64String).urlEncoded
    }

    /// Encodes an array of bytes into a base64 string
    /// - Returns: A base64-encoded string
    public func base64Encoded() -> EncodedBase64 {
        return .init(value: Data(bytes: self, count: self.count).base64EncodedString())
    }
}

extension Data {
    /// Encodes data into a base64url-encoded string
    /// - Returns: A base64url-encoded string
    public func base64URLEncodedString() -> URLEncodedBase64 {
        return [UInt8](self).base64URLEncoded()
    }
}

extension String {
    func toBase64() -> EncodedBase64 {
        return .init(value: Data(self.utf8).base64EncodedString())
    }
}
