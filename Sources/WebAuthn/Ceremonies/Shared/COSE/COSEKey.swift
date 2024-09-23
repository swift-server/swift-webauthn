//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2023 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift WebAuthn project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftCBOR

enum COSEKey: Sendable {
    // swiftlint:disable identifier_name
    case kty
    case alg

    // EC2, OKP
    case crv
    case x

    // EC2
    case y

    // RSA
    case n
    case e
    // swiftlint:enable identifier_name

    var cbor: CBOR {
        var value: Int
        switch self {
        case .kty:
            value = 1
        case .alg:
            value = 3
        case .crv:
            value = -1
        case .x:
            value = -2
        case .y:
            value = -3
        case .n:
            value = -1
        case .e:
            value = -2
        }
        if value < 0 {
            return .negativeInt(UInt64(abs(-1 - value)))
        } else {
            return .unsignedInt(UInt64(value))
        }
    }
}
