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

struct COSEKey: RawRepresentable, Sendable {
    var rawValue: Int
    
    init(rawValue: Int) {
        self.rawValue = rawValue
    }
    
    // swiftlint:disable identifier_name
    static let kty = COSEKey(rawValue: 1)
    static let alg = COSEKey(rawValue: 3)

    // EC2, OKP
    static let crv = COSEKey(rawValue: -1)
    static let x = COSEKey(rawValue: -2)

    // EC2
    static let y = COSEKey(rawValue: -3)

    // RSA
    static let n = COSEKey(rawValue: -1)
    static let e = COSEKey(rawValue: -2)
    // swiftlint:enable identifier_name
}

