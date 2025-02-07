//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2024 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

extension BidirectionalCollection where Element == UInt8 {
    /// Cast a byte sequence into a trivial type like a primitive or a tuple of primitives.
    ///
    /// - Note: It is up to the caller to verify the receiver's size before casting it.
    @inlinable
    func casting<R>() -> R {
        precondition(self.count == MemoryLayout<R>.size, "self.count (\(self.count)) does not match MemoryLayout<R>.size (\(MemoryLayout<R>.size))")
        
        let result = self.withContiguousStorageIfAvailable({
            $0.withUnsafeBytes { $0.loadUnaligned(as: R.self) }
        }) ?? Array(self).withUnsafeBytes {
            $0.loadUnaligned(as: R.self)
        }
        
        return result
    }
}

extension FixedWidthInteger {
    /// Initialize a fixed width integer from a contiguous sequence of Bytes representing a big endian type.
    /// - Parameter bigEndianBytes: The Bytes to interpret as a big endian integer.
    @inlinable
    init(bigEndianBytes: some BidirectionalCollection<UInt8>) {
        self.init(bigEndian: bigEndianBytes.casting())
    }

    /// Initialize a fixed width integer from a contiguous sequence of Bytes representing a little endian type.
    /// - Parameter bigEndianBytes: The Bytes to interpret as a little endian integer.
    @inlinable
    init(littleEndianBytes: some BidirectionalCollection<UInt8>) {
        self.init(littleEndian: littleEndianBytes.casting())
    }
}
