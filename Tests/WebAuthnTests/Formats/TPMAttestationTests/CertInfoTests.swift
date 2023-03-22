// //===----------------------------------------------------------------------===//
// //
// // This source file is part of the WebAuthn Swift open source project
// //
// // Copyright (c) 2022 the WebAuthn Swift project authors
// // Licensed under Apache License v2.0
// //
// // See LICENSE.txt for license information
// // See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
// //
// // SPDX-License-Identifier: Apache-2.0
// //
// //===----------------------------------------------------------------------===//

// @testable import WebAuthn
// import XCTest

// final class CertInfoTests: XCTestCase {
//     func testInitReturnsNilIfDataIsTooShort() {
//         XCTAssertNil(TPMAttestation.CertInfo(fromBytes: Data([UInt8](repeating: 0, count: 8))))
//         XCTAssertNil(TPMAttestation.CertInfo(fromBytes: Data()))
//     }

//     func testVerifyThrowsIfMagicIsInvalid() throws {
//         let certInfo = TPMAttestation.CertInfo(fromBytes: Data([UInt8](repeating: 0, count: 80)))!
//         try assertThrowsError(certInfo.verify(), expect: TPMAttestation.CertInfoError.magicInvalid)
//     }

//     func testVerifyThrowsIfTypeIsInvalid() throws {
//         let certInfoBytes: [UInt8] = [0xFF, 0x54, 0x43, 0x47] + [UInt8](repeating: 0, count: 80)
//         let certInfo = TPMAttestation.CertInfo(fromBytes: Data(certInfoBytes))!
//         try assertThrowsError(certInfo.verify(), expect: TPMAttestation.CertInfoError.typeInvalid)
//     }
// }
