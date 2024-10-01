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
import SwiftCBOR

extension CBOR {
    subscript(key: COSEKey) -> CBOR? {
        get { self[.signedInt(key)] }
        set { self[.signedInt(key)] = newValue }
    }
    
    static func encodeSortedPairs(_ pairs: [(COSEKey, CBOR)], options: CBOROptions = CBOROptions()) -> [UInt8] {
        encodeSortedPairs(pairs.map { (CBOR.signedInt($0), $1) }, options: options)
    }
}

extension CBOR {
    static func signedInt(_ int: some SignedInteger) -> CBOR {
        if int < 0 {
            return .negativeInt(UInt64(abs(-1 - int)))
        } else {
            return .unsignedInt(UInt64(int))
        }
    }
    
    static func signedInt<T: RawRepresentable>(_ rawInt: T) -> CBOR where T.RawValue: SignedInteger {
        .signedInt(rawInt.rawValue)
    }
    
    static func signedInt<T: RawRepresentable>(_ rawInt: T) -> CBOR where T.RawValue: UnsignedInteger {
        .unsignedInt(UInt64(rawInt.rawValue))
    }
}

extension CBOR {
    /// Adapted from SwiftCBOR's ``CBOR/encodeMap(_:options:)`` to account for the [CTAP2 canonical CBOR encoding form](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ctap2-canonical-cbor-encoding-form).
    static func encodeSortedPairs<Key: CBOREncodable, Value: CBOREncodable>(_ pairs: [(Key, Value)], options: CBOROptions = CBOROptions()) -> [UInt8] {
        var res: [UInt8] = []
        res.reserveCapacity(1 + pairs.count * (MemoryLayout<Key>.size + MemoryLayout<Value>.size + 2))
        res = pairs.count.encode(options: options)
        res[0] = res[0] | 0b101_00000
        for (k, v) in pairs {
            res.append(contentsOf: k.encode(options: options))
            res.append(contentsOf: v.encode(options: options))
        }
        return res
    }
}

extension UnsignedInteger {
    init?(_ cbor: CBOR) {
        switch cbor {
        case .unsignedInt(let positiveInt):
            self = Self(positiveInt)
        default: return nil
        }
    }
}

extension SignedInteger {
    init?(_ cbor: CBOR) {
        switch cbor {
        case .unsignedInt(let positiveInt): 
            self = Self(positiveInt)
        case .negativeInt(let negativeInt):
            // https://github.com/unrelentingtech/SwiftCBOR#swiftcbor
            // Negative integers are decoded as NegativeInt(UInt), where the actual number is -1 - i
            self = -1 - Self(negativeInt)
        default: return nil
        }
    }
}
