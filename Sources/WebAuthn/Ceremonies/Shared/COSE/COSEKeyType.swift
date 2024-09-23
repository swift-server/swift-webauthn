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

import Foundation

/// The Key Type derived from the IANA COSE AuthData
enum COSEKeyType: UInt64, RawRepresentable, Sendable {
    /// OctetKey is an Octet Key
	case octetKey = 1
	/// EllipticKey is an Elliptic Curve Public Key
	case ellipticKey = 2
	/// RSAKey is an RSA Public Key
	case rsaKey = 3
}
