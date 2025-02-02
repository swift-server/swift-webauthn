//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2023 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

public extension KeyedDecodingContainer {
    func decodeBytesFromURLEncodedBase64(forKey key: KeyedDecodingContainer.Key) throws -> [UInt8] {
        guard let bytes = try decode(
            URLEncodedBase64.self,
            forKey: key
        ).decodedBytes else {
            throw DecodingError.dataCorruptedError(
                forKey: key,
                in: self,
                debugDescription: "Failed to decode base64url encoded string at \(key) into bytes"
            )
        }
        return bytes
    }

    func decodeBytesFromURLEncodedBase64IfPresent(forKey key: KeyedDecodingContainer.Key) throws -> [UInt8]? {
        guard let bytes = try decodeIfPresent(
            URLEncodedBase64.self,
            forKey: key
        ) else { return nil }

        guard let decodedBytes = bytes.decodedBytes else {
            throw DecodingError.dataCorruptedError(
                forKey: key,
                in: self,
                debugDescription: "Failed to decode base64url encoded string at \(key) into bytes"
            )
        }
        return decodedBytes
    }
}
