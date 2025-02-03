//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2024 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

public protocol AuthenticatorCredentialSourceIdentifier: Hashable, Sendable {
    init?(bytes: some BidirectionalCollection<UInt8>)
    var bytes: [UInt8] { get }
}

extension UUID: AuthenticatorCredentialSourceIdentifier {
    public init?(bytes: some BidirectionalCollection<UInt8>) {
        let uuidSize = MemoryLayout<uuid_t>.size
        guard bytes.count == uuidSize else { return nil }
        
        /// Either load it directly, or copy it to a new array to load the uuid from there.
        let uuid = bytes.withContiguousStorageIfAvailable {
            $0.withUnsafeBytes {
                $0.loadUnaligned(as: uuid_t.self)
            }
        } ?? Array(bytes).withUnsafeBytes {
            $0.loadUnaligned(as: uuid_t.self)
        }
        self = UUID(uuid: uuid)
    }
    
    public var bytes: [UInt8] { withUnsafeBytes(of: self) { Array($0) } }
}
