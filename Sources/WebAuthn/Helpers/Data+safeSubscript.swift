//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2023 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

extension Data {
    struct IndexOutOfBounds: Error {}

    subscript(safe range: Range<Int>) -> Data? {
        let actualRange = range.lowerBound + self.startIndex..<range.upperBound+self.startIndex
        guard count >= range.upperBound else { return nil }
        return self[actualRange]
    }

    /// Safely slices bytes from `pointer` to `pointer` + `length`. Updates the pointer afterwards.
    /// - Returns: The sliced bytes or nil if we're out of bounds.
    func safeSlice(length: Int, using pointer: inout Int) -> Data? {
        guard let value = self[safe: pointer..<(pointer + length)] else { return nil }
        pointer += length
        return value
    }
}
