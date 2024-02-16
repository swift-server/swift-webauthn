//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2024 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
@preconcurrency import Crypto

public struct KeyPairAuthenticator: AuthenticatorProtocol, Sendable {
    public let attestationGloballyUniqueID: AAGUID
    public let attachmentModality: AuthenticatorAttachment
    public let supportedPublicKeyCredentialParameters: Set<PublicKeyCredentialParameters>
    public let canPerformUserVerification: Bool = true
    public let canStoreCredentialSourceClientSide: Bool = true
    
    /// The specific subset the client fully supports, in case more are added over time.
    static let implementedPublicKeyCredentialParameterSubset: Set<PublicKeyCredentialParameters> = [
        PublicKeyCredentialParameters(alg: .algES256),
        PublicKeyCredentialParameters(alg: .algES384),
        PublicKeyCredentialParameters(alg: .algES512),
    ]
    
    /// Generate credentials for the full subset the implementation supports.
    ///
    /// This list must match those supported in ``KeyPairAuthenticator/implementedPublicKeyCredentialParameterSubset``.
    static func generateCredentialSourceKey(for chosenCredentialParameters: PublicKeyCredentialParameters) -> CredentialSource.Key {
        switch chosenCredentialParameters.alg {
        case .algES256: .es256(P256.Signing.PrivateKey(compactRepresentable: false))
        case .algES384: .es384(P384.Signing.PrivateKey(compactRepresentable: false))
        case .algES512: .es521(P521.Signing.PrivateKey(compactRepresentable: false))
        }
    }
    
    /// Initialize a key-pair based authenticator with a globally unique ID representing your application.
    /// - Note: To generate an AAGUID, run `% uuidgen` in your terminal. This value should generally not change across installations or versions of your app, and should be the same for every user.
    /// - Parameter attestationGloballyUniqueID: The AAGUID associated with the authenticator.
    /// - Parameter attachmentModality: The connected-nature of the authenticator to the device the client is running on. If credential keys can roam between devices, specify ``AuthenticatorModality/crossPlatform``. Set to ``AuthenticatorModality/platform`` by default.
    /// - Parameter supportedPublicKeyCredentialParameters: A customized set of key credentials the authenticator will limit support to.
    public init(
        attestationGloballyUniqueID: AAGUID,
        attachmentModality: AuthenticatorAttachment = .platform,
        supportedPublicKeyCredentialParameters: Set<PublicKeyCredentialParameters> = .supported
    ) {
        self.attestationGloballyUniqueID = attestationGloballyUniqueID
        self.attachmentModality = attachmentModality
        self.supportedPublicKeyCredentialParameters = supportedPublicKeyCredentialParameters.intersection(Self.implementedPublicKeyCredentialParameterSubset)
    }
    
    public func generateCredentialSource(
        requiresClientSideKeyStorage: Bool,
        credentialParameters: PublicKeyCredentialParameters,
        relyingPartyID: PublicKeyCredentialRelyingPartyEntity.ID,
        userHandle: PublicKeyCredentialUserEntity.ID
    ) async throws -> CredentialSource {
        CredentialSource(
            id: UUID(),
            key: Self.generateCredentialSourceKey(for: credentialParameters),
            relyingPartyID: relyingPartyID,
            userHandle: userHandle, 
            counter: 0
        )
    }
    
    public func filteredCredentialDescriptors(
        credentialDescriptors: [PublicKeyCredentialDescriptor],
        relyingPartyID: PublicKeyCredentialRelyingPartyEntity.ID
    ) -> [PublicKeyCredentialDescriptor] {
        return credentialDescriptors
    }
    
    public func collectAuthorizationGesture(
        requiresUserVerification: Bool,
        requiresUserPresence: Bool,
        credentialOptions: [CredentialSource]
    ) async throws -> CredentialSource {
        guard let credentialSource = credentialOptions.first
        else { throw WebAuthnError.authorizationGestureNotAllowed }
        
        return credentialSource
    }
}

extension KeyPairAuthenticator {
    public struct CredentialSource: AuthenticatorCredentialSourceProtocol, Sendable {
        public enum Key: Sendable {
            case es256(P256.Signing.PrivateKey)
            case es384(P384.Signing.PrivateKey)
            case es521(P521.Signing.PrivateKey)
        }
        
        public var id: UUID
        public var key: Key
        public var relyingPartyID: PublicKeyCredentialRelyingPartyEntity.ID
        public var userHandle: PublicKeyCredentialUserEntity.ID
        public var counter: UInt32
        
        public var credentialParameters: PublicKeyCredentialParameters {
            switch key {
            case .es256: PublicKeyCredentialParameters(alg: .algES256)
            case .es384: PublicKeyCredentialParameters(alg: .algES384)
            case .es521: PublicKeyCredentialParameters(alg: .algES512)
            }
        }
        
        public var rawKeyData: Data {
            switch key {
            case .es256(let privateKey): privateKey.rawRepresentation
            case .es384(let privateKey): privateKey.rawRepresentation
            case .es521(let privateKey): privateKey.rawRepresentation
            }
        }
        
        public var publicKey: PublicKey {
            switch key {
            case .es256(let privateKey): EC2PublicKey(privateKey.publicKey)
            case .es384(let privateKey): EC2PublicKey(privateKey.publicKey)
            case .es521(let privateKey): EC2PublicKey(privateKey.publicKey)
            }
        }
        
        public init(
            id: ID,
            key: Key,
            relyingPartyID: PublicKeyCredentialRelyingPartyEntity.ID,
            userHandle: PublicKeyCredentialUserEntity.ID,
            counter: UInt32
        ) {
            self.id = id
            self.key = key
            self.relyingPartyID = relyingPartyID
            self.userHandle = userHandle
            self.counter = 0
        }
        
        public init(
            id: ID,
            credentialParameters: PublicKeyCredentialParameters,
            rawKeyData: some ContiguousBytes,
            relyingPartyID: PublicKeyCredentialRelyingPartyEntity.ID,
            userHandle: PublicKeyCredentialUserEntity.ID,
            counter: UInt32
        ) throws {
            guard credentialParameters.type == .publicKey
            else { throw WebAuthnError.unsupportedCredentialPublicKeyType }
            
            self.id = id
            switch credentialParameters.alg {
            case .algES256: key = .es256(try P256.Signing.PrivateKey(rawRepresentation: rawKeyData))
            case .algES384: key = .es384(try P384.Signing.PrivateKey(rawRepresentation: rawKeyData))
            case .algES512: key = .es521(try P521.Signing.PrivateKey(rawRepresentation: rawKeyData))
            }
            self.relyingPartyID = relyingPartyID
            self.userHandle = userHandle
            self.counter = counter
        }
        
        public func signAssertion(
            authenticatorData: [UInt8],
            clientDataHash: SHA256Digest
        ) throws -> [UInt8] {
            let digest = authenticatorData + clientDataHash
            return switch key {
            case .es256(let privateKey): Array(try privateKey.signature(for: digest).derRepresentation)
            case .es384(let privateKey): Array(try privateKey.signature(for: digest).derRepresentation)
            case .es521(let privateKey): Array(try privateKey.signature(for: digest).derRepresentation)
            }
        }
    }
}

extension KeyPairAuthenticator.CredentialSource: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        try self.init(
            id: try container.decode(UUID.self, forKey: .id),
            credentialParameters: try container.decode(PublicKeyCredentialParameters.self, forKey: .credentialParameters),
            rawKeyData: try container.decode(Data.self, forKey: .key),
            relyingPartyID: try container.decode(String.self, forKey: .relyingPartyID),
            userHandle: PublicKeyCredentialUserEntity.ID(try container.decode(Data.self, forKey: .userHandle)),
            counter: try container.decode(UInt32.self, forKey: .counter)
        )
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(id, forKey: .id)
        try container.encode(credentialParameters, forKey: .credentialParameters)
        try container.encode(rawKeyData, forKey: .key)
        try container.encode(relyingPartyID, forKey: .relyingPartyID)
        try container.encode(Data(userHandle), forKey: .userHandle)
        try container.encode(counter, forKey: .counter)
    }
    
    enum CodingKeys: CodingKey {
        case id
        case credentialParameters
        case key
        case relyingPartyID
        case userHandle
        case counter
    }
}
