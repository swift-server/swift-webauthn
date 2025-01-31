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

@testable import WebAuthn
import XCTest
import Crypto

final class WebAuthnManagerChallengeTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!
    
    let relyingPartyID = "example.com"
    let relyingPartyName = "Testy test"
    let relyingPartyOrigin = "https://example.com"
    
    override func setUp() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: relyingPartyID,
            relyingPartyName: relyingPartyName,
            relyingPartyOrigin: relyingPartyOrigin
        )
        webAuthnManager = .init(configuration: configuration)
    }

    func testChallengeData() async throws {
        let challengeGenerator = ChallengeGenerator.live
        let challengeData : [UInt8] = [12,15,48,64]
        
        let challenge =  challengeGenerator.generate(challengeData)
        let extractedData =  webAuthnManager.extractChallengeData(challenge: challenge)
        
        XCTAssertEqual(challengeData, extractedData)
    }
}
