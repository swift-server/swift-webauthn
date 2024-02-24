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

import Crypto
import SwiftCBOR

public protocol AuthenticatorProtocol<CredentialSource> {
    associatedtype CredentialSource: AuthenticatorCredentialSourceProtocol
    
    var attestationGloballyUniqueID: AAGUID { get }
    var attachmentModality: AuthenticatorAttachment { get }
    var supportedPublicKeyCredentialParameters: Set<PublicKeyCredentialParameters> { get }
    var canPerformUserVerification: Bool { get }
    var canStoreCredentialSourceClientSide: Bool { get }
    
    /// Generate a credential source for this authenticator.
    /// - Parameters:
    ///   - requiresClientSideKeyStorage: `true` if the relying party requires that the credential ID is stored client size, as it won't be provided during authentication requests.
    ///   - credentialParameters: The chosen credential parameters.
    ///   - relyingPartyID: The ID of the relying party the credential is being generated for.
    ///   - userHandle: The user handle the credential is being generated for.
    /// - Returns: A new credential source to be returned to the caller upon successful registration.
    func generateCredentialSource(
        requiresClientSideKeyStorage: Bool,
        credentialParameters: PublicKeyCredentialParameters,
        relyingPartyID: PublicKeyCredentialRelyingPartyEntity.ID,
        userHandle: PublicKeyCredentialUserEntity.ID
    ) async throws -> CredentialSource
    
    /// The preferred attestation format for the authenticator, optionally taking into account the provided list of formats the relying party prefers.
    /// 
    /// The default implementation returns ``AttestationFormat/none``.
    ///
    /// - Parameter attestationFormats: A list of attestation formats the relying party prefers.
    /// - Returns: The attestation format that will be used to sign an attestation statement.
    func preferredAttestationFormat(from attestationFormats: [AttestationFormat]) -> AttestationFormat
    
    /// Sign an attestation statement for the provided authenticator data and client data using the specified format.
    /// - Parameters:
    ///   - attestationFormat: The attestation format to sign with.
    ///   - authenticatorData: The authenticator data to be signed.
    ///   - clientDataHash: The client data to be signed.
    /// - Returns: A signiture in the specified format.
    func signAttestationStatement(
        attestationFormat: AttestationFormat,
        authenticatorData: [UInt8],
        clientDataHash: SHA256.Digest
    ) async throws -> CBOR
    
    /// Make credentials for the specified registration request, returning the credential source that the caller should store for subsequent authentication.
    ///
    /// - Important: Depending on the authenticator being used, the credential source may contain private keys, and must be stored sequirely, such as in the user's Keychain, or in a Hardware Security Module appropriate with the level of security you wish to secure your user's account with.
    func makeCredentials(with registration: AttestationRegistrationRequest) async throws -> CredentialSource
    
    /// Filter the provided credential descriptors to determine which, if any, should be handled by this authenticator.
    /// 
    /// This method should execute a client platform-specific procedure to determine which, if any, public key credentials described by `pkOptions.allowCredentials` are bound to this authenticator, by matching with `rpId`, `pkOptions.allowCredentials.id`, and `pkOptions.allowCredentials.type`
    /// 
    /// The default implementation returns the list as is.
    /// - Parameters:
    ///   - credentialDescriptors: A list of credentials that will be used assert authorization against.
    ///   - relyingPartyID: The relying party ID the credentials belong to.
    /// - Returns: A filtered list of credentials that are suitable for this authenticator.
    func filteredCredentialDescriptors(
        credentialDescriptors: [PublicKeyCredentialDescriptor],
        relyingPartyID: PublicKeyCredentialRelyingPartyEntity.ID
    ) -> [PublicKeyCredentialDescriptor]
    
    /// Collect an authorization gesture from the user for one of the specified credential sources, making sure to increment the counter for the credential source if relevant.
    /// - Parameters:
    ///   - requiresUserVerification: The user is required to verify that the credential should be used to assert authorization. If the user cannot perform this task, this method should throw an error.
    ///   - requiresUserPresence: The user is required to be present in order for authorization to be attempted. ie. authorization should not be done in the background without the user's knowledge while they are away from this device.
    ///   - credentialOptions: A list of available credentials to verify against.
    /// - Returns: The chosen credential to use for authorization.
    func collectAuthorizationGesture(
        requiresUserVerification: Bool,
        requiresUserPresence: Bool,
        credentialOptions: [CredentialSource]
    ) async throws -> CredentialSource
}

// MARK: - Default Implementations

extension AuthenticatorProtocol {
    public func preferredAttestationFormat(
        from attestationFormats: [AttestationFormat]
    ) -> AttestationFormat {
        .none
    }
    
    public func signAttestationStatement(
        attestationFormat: AttestationFormat,
        authenticatorData: [UInt8],
        clientDataHash: SHA256.Digest
    ) async throws -> CBOR {
        guard attestationFormat == .none
        else { throw WebAuthnError.attestationFormatNotSupported }
        
        return [:]
    }
    
    public func filteredCredentialDescriptors(
        credentialDescriptors: [PublicKeyCredentialDescriptor],
        relyingPartyID: PublicKeyCredentialRelyingPartyEntity.ID
    ) -> [PublicKeyCredentialDescriptor] {
        return credentialDescriptors
    }
}

// MARK: Registration

extension AuthenticatorProtocol {
    public func makeCredentials(
        with registration: AttestationRegistrationRequest
    ) async throws -> CredentialSource {
        throw WebAuthnError.unsupported
    }
}
