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
import Crypto
import SwiftCBOR

/// Data created and/ or used by the authenticator during authentication/ registration.
/// The data contains, for example, whether a user was present or verified.
public struct AuthenticatorData: Equatable, Sendable {
    var relyingPartyIDHash: [UInt8]
    var flags: AuthenticatorFlags
    var counter: UInt32
    /// For attestation signatures this value will be set. For assertion signatures not.
    var attestedData: AttestedCredentialData?
    var extData: [UInt8]?

    init(
        relyingPartyIDHash: SHA256Digest,
        flags: AuthenticatorFlags,
        counter: UInt32,
        attestedData: AttestedCredentialData? = nil,
        extData: [UInt8]? = nil
    ) {
        self.relyingPartyIDHash = Array(relyingPartyIDHash)
        var flags = flags
        flags.attestedCredentialData = attestedData != nil
        flags.extensionDataIncluded = extData != nil
        self.flags = flags
        self.counter = counter
        self.attestedData = attestedData
        self.extData = extData
    }
}

extension AuthenticatorData {
    init(bytes: [UInt8]) throws {
        let minAuthDataLength = 37
        guard bytes.count >= minAuthDataLength else {
            throw WebAuthnError.authDataTooShort
        }

        let relyingPartyIDHash = Array(bytes[..<32])
        let flags = AuthenticatorFlags(bytes[32])
        let counter = UInt32(bigEndianBytes: bytes[33..<37])

        var remainingCount = bytes.count - minAuthDataLength

        var attestedCredentialData: AttestedCredentialData?
        // For attestation signatures, the authenticator MUST set the AT flag and include the attestedCredentialData.
        if flags.attestedCredentialData {
            let minAttestedAuthLength = 37 + AAGUID.size + 2
            guard bytes.count > minAttestedAuthLength else {
                throw WebAuthnError.attestedCredentialDataMissing
            }
            let (data, length) = try Self.parseAttestedData(bytes)
            attestedCredentialData = data
            remainingCount -= length
        // For assertion signatures, the AT flag MUST NOT be set and the attestedCredentialData MUST NOT be included.
        } else {
            if !flags.extensionDataIncluded && bytes.count != minAuthDataLength {
                throw WebAuthnError.attestedCredentialFlagNotSet
            }
        }

        var extensionData: [UInt8]?
        if flags.extensionDataIncluded {
            guard remainingCount != 0 else {
                throw WebAuthnError.extensionDataMissing
            }
            extensionData = Array(bytes[(bytes.count - remainingCount)...])
            remainingCount -= extensionData!.count
        }

        guard remainingCount == 0 else {
            throw WebAuthnError.leftOverBytesInAuthenticatorData
        }

        self.relyingPartyIDHash = relyingPartyIDHash
        self.flags = flags
        self.counter = counter
        self.attestedData = attestedCredentialData
        self.extData = extensionData

    }

    /// Parse and return the attested credential data and its length.
    ///
    /// This is assumed to take place after the first 37 bytes of `data`, which is always of fixed size.
    /// - SeeAlso: [WebAuthn Level 3 Editor's Draft §6.5.1. Attested Credential Data]( https://w3c.github.io/webauthn/#sctn-attested-credential-data)
    private static func parseAttestedData(_ data: [UInt8]) throws -> (AttestedCredentialData, Int) {
        /// **aaguid** (16): The AAGUID of the authenticator.
        guard let aaguid = AAGUID(bytes: data[37..<(37 + AAGUID.size)])  // Bytes [37-52]
        else { throw WebAuthnError.attestedCredentialDataMissing }

        /// **credentialIdLength** (2): Byte length L of credentialId, 16-bit unsigned big-endian integer. Value MUST be ≤ 1023.
        let idLengthBytes = data[53..<55]  // Length is 2 bytes
        let idLengthData = Data(idLengthBytes)
        let idLength = UInt16(bigEndianBytes: idLengthData)

        guard idLength <= 1023
        else { throw WebAuthnError.credentialIDTooLong }

        let credentialIDEndIndex = Int(idLength) + 55
        guard data.count >= credentialIDEndIndex 
        else { throw WebAuthnError.credentialIDTooShort }

        /// **credentialId** (L): Credential ID
        let credentialID = data[55..<credentialIDEndIndex]

        /// **credentialPublicKey** (variable): The credential public key encoded in `COSE_Key` format, as defined in [Section 7](https://tools.ietf.org/html/rfc9052#section-7) of [RFC9052], using the CTAP2 canonical CBOR encoding form.
        /// Assuming valid CBOR, verify the public key's length by decoding the next CBOR item.
        let inputStream = ByteInputStream(data[credentialIDEndIndex...])
        let decoder = CBORDecoder(stream: inputStream, options: CBOROptions(maximumDepth: 16))
        _ = try decoder.decodeItem()
        let publicKeyBytes = data[credentialIDEndIndex..<(data.count - inputStream.remainingBytes)]

        let data = AttestedCredentialData(
            authenticatorAttestationGUID: aaguid,
            credentialID: Array(credentialID),
            publicKey: Array(publicKeyBytes)
        )

        /// `2` is the size of **credentialIdLength**
        let length = AAGUID.size + 2 + data.credentialID.count + data.publicKey.count

        return (data, length)
    }
    
    public var bytes: [UInt8] {
        assert(relyingPartyIDHash.count == 32, "AuthenticatorData contains relyingPartyIDHash of length \(relyingPartyIDHash.count), which will likely not be decodable.")
        var bytes: [UInt8] = []
        
        bytes += relyingPartyIDHash
        bytes += flags.bytes
        bytes += withUnsafeBytes(of: UInt32(counter).bigEndian) { Array($0) }
        
        assert((!flags.attestedCredentialData && attestedData == nil) || (flags.attestedCredentialData && attestedData != nil), "AuthenticatorData contains mismatch between attestedCredentialData flag and attestedData, which will likely not be decodable.")
        if flags.attestedCredentialData, let attestedData {
            bytes += attestedData.authenticatorAttestationGUID.bytes
            bytes += withUnsafeBytes(of: UInt16(attestedData.credentialID.count).bigEndian) { Array($0) }
            bytes += attestedData.credentialID
            bytes += attestedData.publicKey
        }
        
        assert((!flags.extensionDataIncluded && extData == nil) || (flags.extensionDataIncluded && extData != nil), "AuthenticatorData contains mismatch between extensionDataIncluded flag and extData, which will likely not be decodable.")
        if flags.extensionDataIncluded, let extData {
            bytes += extData
        }
        return bytes
    }
}

/// A helper type to determine how many bytes were consumed when decoding CBOR items.
class ByteInputStream: CBORInputStream {
    private var slice : ArraySlice<UInt8>
    
    init(_ slice: ArraySlice<UInt8>) {
        self.slice = slice
    }
    
    /// The remaining bytes in the original data buffer.
    var remainingBytes: Int { slice.count }
    
    func popByte() throws -> UInt8 {
        if slice.count < 1 { throw CBORError.unfinishedSequence }
        return slice.removeFirst()
    }
    
    func popBytes(_ n: Int) throws -> ArraySlice<UInt8> {
        if slice.count < n { throw CBORError.unfinishedSequence }
        let result = slice.prefix(n)
        slice = slice.dropFirst(n)
        return result
    }
}
