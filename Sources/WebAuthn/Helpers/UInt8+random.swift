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

extension FixedWidthInteger {
    public static func random() -> Self {
        return Self.random(in: .min ... .max)
    }

    public static func random<T>(using generator: inout T) -> Self where T: RandomNumberGenerator {
        return Self.random(in: .min ... .max, using: &generator)
    }
}

extension Array where Element: FixedWidthInteger {
    public static func random(count: Int) -> [Element] {
        var array: [Element] = .init(repeating: 0, count: count)
        (0..<count).forEach { array[$0] = Element.random() }
        return array
    }

    public static func random<T>(count: Int, using generator: inout T) -> [Element] where T: RandomNumberGenerator {
        var array: [Element] = .init(repeating: 0, count: count)
        (0..<count).forEach { array[$0] = Element.random(using: &generator) }
        return array
    }
}
