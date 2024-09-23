//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift WebAuthn project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// An enumeration type that is not referenced by other parts of the Web IDL because that would preclude other values from being used without updating the specification and its implementations.
/// - SeeAlso: [WebAuthn Level 3 Editor's Draft §2.1.1. Enumerations as DOMString types](https://w3c.github.io/webauthn/#sct-domstring-backwards-compatibility)
public protocol UnreferencedStringEnumeration: RawRepresentable, Codable, Sendable, ExpressibleByStringLiteral, Hashable, Comparable where RawValue == String {
    init(_ rawValue: RawValue)
}

extension UnreferencedStringEnumeration {
    public init(rawValue: RawValue) {
        self.init(rawValue)
    }
    
    public init(stringLiteral value: String) {
        self.init(value)
    }
    
    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}
