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

import Foundation
import SwiftASN1
import X509

// Based on https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
struct AndroidKeyVerificationPolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.basicConstraints,
        .X509ExtensionID.nameConstraints,
        .X509ExtensionID.subjectAlternativeName,
        .X509ExtensionID.keyUsage,
    ]

    private let clientDataHash: [UInt8]
    
    init(clientDataHash: Data) {
        self.clientDataHash = Array(clientDataHash)
    }
    
    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        let leaf = chain.leaf

        // https://www.w3.org/TR/webauthn-2/#sctn-key-attstn-cert-requirements
        guard let androidExtension = leaf.extensions[oid: .androidAttestation] else {
            return .failsToMeetPolicy(
                reason: "Required extension \(ASN1ObjectIdentifier.androidAttestation) not present: \(leaf)"
            )
        }

        let keyDesc: AndroidKeyDescription!
        do {
            keyDesc = try AndroidKeyDescription(derEncoded: androidExtension.value)
        }
        catch let error {
            return .failsToMeetPolicy(
                reason: "Error parsing KeyDescription extension (\(ASN1ObjectIdentifier.androidAttestation)): \(error): \(leaf)"
            )
        }

        // Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
        guard Array(keyDesc.attestationChallenge.bytes) == clientDataHash else {
            return .failsToMeetPolicy(
                reason: "Challenge hash in keyDescription does not match clientDataHash: \(leaf)"
            )
        }

        // Allow authenticator keys that were either generated in secure hardware or in software
        guard keyDesc.softwareEnforced.origin == 0 && keyDesc.teeEnforced.origin == 0 else {
            return .failsToMeetPolicy(
                reason: "keyDescription says authenticator key was not hardware or software generated: \(leaf)"
            )
        }

        // Key must be dedicated to the RP ID
        guard keyDesc.softwareEnforced.allApplications == nil && keyDesc.teeEnforced.allApplications == nil else {
            return .failsToMeetPolicy(
                reason: "keyDescription says authenticator key is for all aplications: \(leaf)"
            )
        }

        // Key must have a signing purpose
        guard keyDesc.softwareEnforced.purpose.contains(.sign) || keyDesc.teeEnforced.purpose.contains(.sign) else {
            return .failsToMeetPolicy(
                reason: "keyDescription says authenticator key is not for signing: \(leaf)"
            )
        }

        return .meetsPolicy
    }
}

// https://source.android.com/docs/security/features/keystore/attestation#schema
struct AndroidKeyDescription: DERImplicitlyTaggable {
    internal init(
        attestationVersion: Int,
        attestationSecurityLevel: ASN1Any,
        keymasterVersion: Int,
        keymasterSecurityLevel: ASN1Any,
        attestationChallenge: ASN1OctetString,
        uniqueID: ASN1OctetString,
        softwareEnforced: AuthorizationList,
        teeEnforced: AuthorizationList
    ) {
        self.attestationVersion = attestationVersion
        self.attestationSecurityLevel = attestationSecurityLevel
        self.keymasterVersion = keymasterVersion
        self.keymasterSecurityLevel = keymasterSecurityLevel
        self.attestationChallenge = attestationChallenge
        self.uniqueID = uniqueID
        self.softwareEnforced = softwareEnforced
        self.teeEnforced = teeEnforced
    }

    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    // We need these fields for verifying the attestation
    var attestationChallenge: ASN1OctetString
    var softwareEnforced: AuthorizationList
    var teeEnforced: AuthorizationList
    // We don't need or care about these fields
    var attestationVersion: Int
    var attestationSecurityLevel: ASN1Any
    var keymasterVersion: Int
    var keymasterSecurityLevel: ASN1Any
    var uniqueID: ASN1OctetString

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes)
            let secLevel = try ASN1Any(derEncoded: &nodes)
            let kMasterVersion = try Int(derEncoded: &nodes)
            let kMasterSecLevel = try ASN1Any(derEncoded: &nodes)
            let challenge = try ASN1OctetString(derEncoded: &nodes)
            let id = try ASN1OctetString(derEncoded: &nodes)
            let softwareEnforced = try AuthorizationList(derEncoded: &nodes)
            let teeEnforced = try AuthorizationList(derEncoded: &nodes)
            return AndroidKeyDescription.init(
                attestationVersion: version,
                attestationSecurityLevel: secLevel,
                keymasterVersion: kMasterVersion,
                keymasterSecurityLevel: kMasterSecLevel,
                attestationChallenge: challenge,
                uniqueID: id,
                softwareEnforced: softwareEnforced,
                teeEnforced: teeEnforced
            )
        }
    }
    
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {}
}

struct AuthorizationList: DERParseable {
    enum KeyPurpose: Int {
        case encrypt, decrypt, sign, verify, derive, wrap
    }
    init(purpose: [KeyPurpose], origin: Int, allApplications: ASN1Any?) {
        self.purpose = purpose
        self.origin = origin
        self.allApplications = allApplications
    }

    // We only need these fields for verifying the attestation
    var purpose: [KeyPurpose] = []
    var origin: Int?
    var allApplications: ASN1Any?

    init(derEncoded rootNode: ASN1Node) throws {
        self = try DER.sequence(rootNode, identifier: .sequence) { nodes in
            var purpose: [KeyPurpose] = []
            _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { node in
                try DER.set(node, identifier: .set) { items in
                    while let item = items.next() {
                        if let intValue = try? Int(derEncoded: item), let currentPurpose = KeyPurpose(rawValue: intValue) {
                            purpose.append(currentPurpose)
                        }
                    }
                }
            }
            
            // We don't care about these fields but must decode them
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                try Int(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 3, tagClass: .contextSpecific) {
                try Int(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 5, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 6, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 10, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 200, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 303, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 400, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 401, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 402, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 503, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 504, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 505, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 506, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 507, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 508, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 509, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }

            let allApplications = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 600, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            
            // We don't care about these fields but must decode them
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 601, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 701, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            
            let origin = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 702, tagClass: .contextSpecific) {
                try Int(derEncoded: $0)
            }
            
            // We don't care about these fields but must decode them
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 703, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 704, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 705, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 706, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 709, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 709, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 709, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 710, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 711, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 712, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 713, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 714, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 715, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 716, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 717, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 718, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            let _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 719, tagClass: .contextSpecific) {
                ASN1Any(derEncoded: $0)
            }
            
            return AuthorizationList(purpose: purpose, origin: origin ?? 0, allApplications: allApplications)
        }
    }
}
