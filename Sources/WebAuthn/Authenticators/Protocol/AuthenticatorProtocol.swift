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
    /// - SeeAlso: [WebAuthn Level 3 Editor's Draft §5.1.3. Create a New Credential - PublicKeyCredential’s Create(origin, options, sameOriginWithAncestors) Method, Step 25.]( https://w3c.github.io/webauthn/#CreateCred-async-loop)
    /// - SeeAlso: [WebAuthn Level 3 Editor's Draft §6.3.2. The authenticatorMakeCredential Operation](https://w3c.github.io/webauthn/#sctn-op-make-cred)
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
        /// See [WebAuthn Level 3 Editor's Draft §5.1.3. Create a New Credential - PublicKeyCredential’s Create(origin, options, sameOriginWithAncestors) Method, Step 25.]( https://w3c.github.io/webauthn/#CreateCred-async-loop)
        /// Step 1. This authenticator is now the candidate authenticator.
        /// Step 2. If pkOptions.authenticatorSelection is present:
        ///     1. If pkOptions.authenticatorSelection.authenticatorAttachment is present and its value is not equal to authenticator’s authenticator attachment modality, continue.
        ///     2. If pkOptions.authenticatorSelection.residentKey
        ///         → is present and set to required
        ///             If the authenticator is not capable of storing a client-side discoverable public key credential source, continue.
        ///         → is present and set to preferred or discouraged
        ///             No effect.
        ///         → is not present
        ///             if pkOptions.authenticatorSelection.requireResidentKey is set to true and the authenticator is not capable of storing a client-side discoverable public key credential source, continue.
        ///     6. If pkOptions.authenticatorSelection.userVerification is set to required and the authenticator is not capable of performing user verification, continue.
        // Skip.
        
        /// Step 3. Let requireResidentKey be the effective resident key requirement for credential creation, a Boolean value, as follows:
        ///     If pkOptions.authenticatorSelection.residentKey
        ///         → is present and set to required
        ///             Let requireResidentKey be true.
        ///         → is present and set to preferred
        ///             If the authenticator
        ///                 → is capable of client-side credential storage modality
        ///                     Let requireResidentKey be true.
        ///                 → is not capable of client-side credential storage modality, or if the client cannot determine authenticator capability,
        ///                     Let requireResidentKey be false.
        ///         → is present and set to discouraged
        ///             Let requireResidentKey be false.
        ///         → is not present
        ///             Let requireResidentKey be the value of pkOptions.authenticatorSelection.requireResidentKey.
        let requiresClientSideKeyStorage = false
        
        /// Step 10. Let userVerification be the effective user verification requirement for credential creation, a Boolean value, as follows. If pkOptions.authenticatorSelection.userVerification
        ///     → is set to required
        ///         Let userVerification be true.
        ///     → is set to preferred
        ///         If the authenticator
        ///             → is capable of user verification
        ///                 Let userVerification be true.
        ///             → is not capable of user verification
        ///                 Let userVerification be false.
        ///     → is set to discouraged
        ///         Let userVerification be false.
        let shouldPerformUserVerification = false
        
        /// Step 16. Let enterpriseAttestationPossible be a Boolean value, as follows. If pkOptions.attestation
        ///     → is set to enterprise
        ///         Let enterpriseAttestationPossible be true if the user agent wishes to support enterprise attestation for pkOptions.rp.id (see Step 8, above). Otherwise false.
        ///     → otherwise
        ///         Let enterpriseAttestationPossible be false.
        let isEnterpriseAttestationPossible = false
        
        /// Step 19. Let attestationFormats be a list of strings, initialized to the value of pkOptions.attestationFormats.
        /// Step 20. If pkOptions.attestation
        ///     → is set to none
        ///         Set attestationFormats be the single-element list containing the string “none”
        guard case .none = registration.options.attestation else { throw WebAuthnError.attestationFormatNotSupported }
        
        /// Step 22. Let excludeCredentialDescriptorList be a new list.
        /// Step 23. For each credential descriptor C in pkOptions.excludeCredentials:
        ///     1. If C.transports is not empty, and authenticator is connected over a transport not mentioned in C.transports, the client MAY continue.
        ///     2. Otherwise, Append C to excludeCredentialDescriptorList.
        ///     3. Invoke the authenticatorMakeCredential operation on authenticator with clientDataHash, pkOptions.rp, pkOptions.user, requireResidentKey, userVerification, credTypesAndPubKeyAlgs, excludeCredentialDescriptorList, enterpriseAttestationPossible, attestationFormats, and authenticatorExtensions as parameters.
        /// Step 24. Append authenticator to issuedRequests.
        
        /// See [WebAuthn Level 3 Editor's Draft §6.3.2. The authenticatorMakeCredential Operation](https://w3c.github.io/webauthn/#sctn-op-make-cred)
        /// Step 1. Check if all the supplied parameters are syntactically well-formed and of the correct length. If not, return an error code equivalent to "UnknownError" and terminate the operation.
        /// Step 2. Check if at least one of the specified combinations of PublicKeyCredentialType and cryptographic parameters in credTypesAndPubKeyAlgs is supported. If not, return an error code equivalent to "NotSupportedError" and terminate the operation.
        guard let chosenCredentialParameters = registration.publicKeyCredentialParameters.first(where: supportedPublicKeyCredentialParameters.contains(_:))
        else { throw WebAuthnError.noSupportedCredentialParameters }
        
        /// Step 3. For each descriptor of excludeCredentialDescriptorList:
        ///     1. If looking up descriptor.id in this authenticator returns non-null, and the returned item's RP ID and type match rpEntity.id and excludeCredentialDescriptorList.type respectively, then collect an authorization gesture confirming user consent for creating a new credential. The authorization gesture MUST include a test of user presence. If the user
        ///         → confirms consent to create a new credential
        ///             return an error code equivalent to "InvalidStateError" and terminate the operation.
        ///         → does not consent to create a new credential
        ///             return an error code equivalent to "NotAllowedError" and terminate the operation.
        ///         NOTE: The purpose of this authorization gesture is not to proceed with creating a credential, but for privacy reasons to authorize disclosure of the fact that descriptor.id is bound to this authenticator. If the user consents, the client and Relying Party can detect this and guide the user to use a different authenticator. If the user does not consent, the authenticator does not reveal that descriptor.id is bound to it, and responds as if the user simply declined consent to create a credential.
        /// Step 4. If requireResidentKey is true and the authenticator cannot store a client-side discoverable public key credential source, return an error code equivalent to "ConstraintError" and terminate the operation.
        /// Step 5. If requireUserVerification is true and the authenticator cannot perform user verification, return an error code equivalent to "ConstraintError" and terminate the operation.
        /// Step 6. Collect an authorization gesture confirming user consent for creating a new credential. The prompt for the authorization gesture is shown by the authenticator if it has its own output capability, or by the user agent otherwise. The prompt SHOULD display rpEntity.id, rpEntity.name, userEntity.name and userEntity.displayName, if possible.
        ///     → If requireUserVerification is true, the authorization gesture MUST include user verification.
        ///     → If requireUserPresence is true, the authorization gesture MUST include a test of user presence.
        ///     → If the user does not consent or if user verification fails, return an error code equivalent to "NotAllowedError" and terminate the operation.
        /// Step 7. Once the authorization gesture has been completed and user consent has been obtained, generate a new credential object:
        ///     1. Let (publicKey, privateKey) be a new pair of cryptographic keys using the combination of PublicKeyCredentialType and cryptographic parameters represented by the first item in credTypesAndPubKeyAlgs that is supported by this authenticator.
        ///     2. Let userHandle be userEntity.id.
        ///     3. Let credentialSource be a new public key credential source with the fields:
        ///         type
        ///             public-key.
        ///         privateKey
        ///             privateKey
        ///         rpId
        ///             rpEntity.id
        ///         userHandle
        ///             userHandle
        ///         otherUI
        ///             Any other information the authenticator chooses to include.
        ///     4. If requireResidentKey is true or the authenticator chooses to create a client-side discoverable public key credential source:
        ///         1. Let credentialId be a new credential id.
        ///         2. Set credentialSource.id to credentialId.
        ///         3. Let credentials be this authenticator’s credentials map.
        ///         4. Set credentials[(rpEntity.id, userHandle)] to credentialSource.
        ///     5. Otherwise:
        ///         Let credentialId be the result of serializing and encrypting credentialSource so that only this authenticator can decrypt it.
        let credentialSource = try await generateCredentialSource(
            requiresClientSideKeyStorage: requiresClientSideKeyStorage, credentialParameters: chosenCredentialParameters,
            relyingPartyID: registration.options.relyingParty.id, userHandle: registration.options.user.id
        )
        
        /// Step 8. If any error occurred while creating the new credential object, return an error code equivalent to "UnknownError" and terminate the operation.
        /// Step 9. Let processedExtensions be the result of authenticator extension processing for each supported extension identifier → authenticator extension input in extensions.
        /// Step 10. If the authenticator:
        ///     → is a U2F device
        ///         let the signature counter value for the new credential be zero. (U2F devices may support signature counters but do not return a counter when making a credential. See [FIDO-U2F-Message-Formats].)
        ///     → supports a global signature counter
        ///         Use the global signature counter's actual value when generating authenticator data.
        ///     → supports a per credential signature counter
        ///         allocate the counter, associate it with the new credential, and initialize the counter value as zero.
        ///     → does not support a signature counter
        ///         let the signature counter value for the new credential be constant at zero.
        /// Step 15. Let attestedCredentialData be the attested credential data byte array including the credentialId and publicKey.
        /// Step 16. Let attestationFormat be the first supported attestation statement format identifier from attestationFormats, taking into account enterpriseAttestationPossible. If attestationFormats contains no supported value, then let attestationFormat be the attestation statement format identifier most preferred by this authenticator.
        /// Step 17. Let authenticatorData be the byte array specified in § 6.1 Authenticator Data, including attestedCredentialData as the attestedCredentialData and processedExtensions, if any, as the extensions.
        /// Step 18. Create an attestation object for the new credential using the procedure specified in § 6.5.4 Generating an Attestation Object, the attestation statement format attestationFormat, and the values authenticatorData and hash, as well as taking into account the value of enterpriseAttestationPossible. For more details on attestation, see § 6.5 Attestation.
        /// On successful completion of this operation, the authenticator returns the attestation object to the client.
//        try await registration.attemptRegistration.submitAttestationObject(
//            attestationFormat: <#T##AttestationFormat#>,
//            authenticatorData: <#T##AuthenticatorData#>,
//            attestationStatement: <#T##CBOR#>
//        )
        
        return credentialSource
    }
}
