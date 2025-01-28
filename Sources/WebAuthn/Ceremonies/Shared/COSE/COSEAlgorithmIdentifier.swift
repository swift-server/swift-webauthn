//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import Crypto

/// COSEAlgorithmIdentifier From §5.10.5. A number identifying a cryptographic algorithm. The algorithm
/// identifiers SHOULD be values registered in the IANA COSE Algorithms registry
/// [https://www.w3.org/TR/webauthn/#biblio-iana-cose-algs-reg], for instance, -7 for "ES256" and -257 for "RS256".
public enum COSEAlgorithmIdentifier: Int, RawRepresentable, CaseIterable, Codable, Sendable {
    /// AlgES256 ECDSA with SHA-256
	case algES256 = -7
	/// AlgES384 ECDSA with SHA-384
	case algES384 = -35
	/// AlgES512 ECDSA with SHA-512
	case algES512 = -36

	// We don't support RSA yet

	// /// AlgRS1 RSASSA-PKCS1-v1_5 with SHA-1
	// case algRS1 = -65535
	// /// AlgRS256 RSASSA-PKCS1-v1_5 with SHA-256
	// case algRS256 = -257
	// /// AlgRS384 RSASSA-PKCS1-v1_5 with SHA-384
	// case algRS384 = -258
	// /// AlgRS512 RSASSA-PKCS1-v1_5 with SHA-512
	// case algRS512 = -259
	// /// AlgPS256 RSASSA-PSS with SHA-256
	// case algPS256 = -37
	// /// AlgPS384 RSASSA-PSS with SHA-384
	// case algPS384 = -38
	// /// AlgPS512 RSASSA-PSS with SHA-512
	// case algPS512 = -39
	// // AlgEdDSA EdDSA
	// case algEdDSA = -8

	func hashAndCompare(data: Data, to compareHash: Data) -> Bool {
		switch self {
		case .algES256:
			return SHA256.hash(data: data) == compareHash
		case .algES384:
			return SHA384.hash(data: data) == compareHash
		case .algES512:
			return SHA512.hash(data: data) == compareHash
		}
	}
}
