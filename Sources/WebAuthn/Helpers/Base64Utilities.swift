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

/// A structure representing a value encoded in Base64 format.
public struct EncodedBase64: Codable, Hashable, Equatable {
    
    /// The Base64-encoded value.
    public let value: String
    
    /// Initialises an EncodedBase64 value from a plain text string.
    /// - Parameter plain: The plain text string to encode.
    public init(plain: String) {
        let data = plain.data(using: .utf8) ?? Data()
        self.value = data.base64EncodedString()
    }
    
    /// Initialises an EncodedBase64 value from a Base64-encoded string.
    /// - Parameter base64Encoded: The Base64-encoded string.
    public init(base64Encoded: String) {
        self.value = base64Encoded
    }
    
    /// Initialises an EncodedBase64 value from an array of bytes.
    /// - Parameter bytes: The array of bytes to encode.
    public init(bytes: [UInt8]) {
        let data = Data(bytes: bytes, count: bytes.count)
        let value = data.base64EncodedString()
        self.init(base64Encoded: value)
    }
    
    /// Initialises an EncodedBase64 value from binary data.
    /// - Parameter data: The binary data to encode.
    public init(data: Data) {
        self.init(bytes: Array(data))
    }
    
    public init(base64URL: URLEncodedBase64) {
        var value = base64URL.value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while value.count % 4 != 0 {
            value = value.appending("=")
        }
        self.init(base64Encoded: value)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(String.self)
        self.init(base64Encoded: value)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.value)
    }

    /// Decodes Base64 string and transforms result into `[UInt8]`
    public var decodedBytes: [UInt8]? {
        guard let data = Data(base64Encoded: self.value) else {
            return nil
        }
        return [UInt8](data)
    }
}

/// A structure representing a value encoded in URL-safe Base64 format.
public struct URLEncodedBase64: Codable, Hashable, Equatable {
    
    /// The URL-safe Base64-encoded value.
    public let value: String
    
    /// Initialises a URLEncodedBase64 value from a plain text string.
    /// - Parameter plain: The plain text string to encode.
    public init(plain: String) {
        let base64 = EncodedBase64(plain: plain)
        self.init(base64: base64)
    }
    
    /// Initialises a URLEncodedBase64 value from a URL-safe Base64-encoded string.
    /// - Parameter base64URLEncoded: The URL-safe Base64-encoded string.
    public init(base64URLEncoded: String) {
        self.value = base64URLEncoded
    }
    
    /// Initialises a URLEncodedBase64 value from binary data.
    /// - Parameter data: The binary data to encode.
    public init(data: Data) {
        let base64Encoded = EncodedBase64(data: data)
        self.init(base64: base64Encoded)
    }
    
    /// Initialises a URLEncodedBase64 value from an array of bytes.
    /// - Parameter bytes: The array of bytes to encode.
    public init(bytes: [UInt8]) {
        let data = Data(bytes: bytes, count: bytes.count)
        let base64Encoded = EncodedBase64(base64Encoded: data.base64EncodedString())
        self.init(base64: base64Encoded)
    }

    /// Decodes Base64URL string and transforms result into `[UInt8]`
    public var decodedBytes: [UInt8]? {
        let base64 = EncodedBase64(base64URL: self)
        return base64.decodedBytes
    }

    public init(base64: EncodedBase64) {
        let value = base64.value
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        self.init(base64URLEncoded: value)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(String.self)
        self.init(base64URLEncoded: value)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.value)
    }
}
