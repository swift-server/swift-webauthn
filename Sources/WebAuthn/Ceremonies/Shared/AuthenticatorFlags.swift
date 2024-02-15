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

public struct AuthenticatorFlags: Equatable, Sendable {

    /**
     Taken from https://w3c.github.io/webauthn/#sctn-authenticator-data
     Bit 0: User Present Result
     Bit 1: Reserved for future use
     Bit 2: User Verified Result
     Bits 3-5: Reserved for future use
     Bit 6: Attested credential data included
     Bit 7: Extension data include
     */

    enum Bit: UInt8 {
        case userPresent = 0
        case userVerified = 2
        case backupEligible = 3
        case backupState = 4
        case attestedCredentialDataIncluded = 6
        case extensionDataIncluded = 7
    }

    let userPresent: Bool
    let userVerified: Bool
    let isBackupEligible: Bool
    let isCurrentlyBackedUp: Bool
    let attestedCredentialData: Bool
    let extensionDataIncluded: Bool

    var deviceType: VerifiedAuthentication.CredentialDeviceType {
        isBackupEligible ? .multiDevice : .singleDevice
    }

    static func isFlagSet(on byte: UInt8, at position: Bit) -> Bool {
        (byte & (1 << position.rawValue)) != 0
    }
}

extension AuthenticatorFlags {
    init(_ byte: UInt8) {
        userPresent = Self.isFlagSet(on: byte, at: .userPresent)
        userVerified = Self.isFlagSet(on: byte, at: .userVerified)
        isBackupEligible = Self.isFlagSet(on: byte, at: .backupEligible)
        isCurrentlyBackedUp = Self.isFlagSet(on: byte, at: .backupState)
        attestedCredentialData = Self.isFlagSet(on: byte, at: .attestedCredentialDataIncluded)
        extensionDataIncluded = Self.isFlagSet(on: byte, at: .extensionDataIncluded)
    }
    
    public var bytes: [UInt8] {
        var byte: UInt8 = 0
        byte |= userPresent ? 1 << Bit.userPresent.rawValue : 0
        byte |= userVerified ? 1 << Bit.userVerified.rawValue : 0
        byte |= isBackupEligible ? 1 << Bit.backupEligible.rawValue : 0
        byte |= isCurrentlyBackedUp ? 1 << Bit.backupState.rawValue : 0
        byte |= attestedCredentialData ? 1 << Bit.attestedCredentialDataIncluded.rawValue : 0
        byte |= extensionDataIncluded ? 1 << Bit.extensionDataIncluded.rawValue : 0
        return [byte]
    }
}
