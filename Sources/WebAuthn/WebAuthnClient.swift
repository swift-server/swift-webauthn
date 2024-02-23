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
import Crypto

/// A client implementation capable of interfacing between an ``AuthenticatorProtocol`` authenticator and the Web Authentication API.
///
/// - Important: Unless you specifically need to implement a custom WebAuthn client, it is vastly preferable to reach for the built-in [AuthenticationServices](https://developer.apple.com/documentation/authenticationservices) framework instead, which provides out-of-the-box support for a user's [Passkey](https://developer.apple.com/documentation/authenticationservices/public-private_key_authentication/supporting_passkeys). However, this is not always possible or preferrable to use this credential, especially when you want to implement silent account creation, and wish to build it off of WebAuthn. For those cases, `WebAuthnClient` is available.
///
/// Registration: To create a registration credential, first ask the relying party (aka the server) for ``PublicKeyCredentialCreationOptions``, then pass those to ``createRegistrationCredential(options:minTimeout:maxTimeout:origin:supportedPublicKeyCredentialParameters:attestRegistration:)`` along with a closure that can generate credentials from configured ``AuthenticatorProtocol`` types such as ``KeyPairAuthenticator`` by passing the provided ``AttestationRegistration`` to ``AuthenticatorProtocol/makeCredentials(with:)``, making sure to persist the resulting ``AuthenticatorProtocol/CredentialSource`` in some way. Finally, pass the resulting ``RegistrationCredential`` back to the relying party to finish registration.
/// Authentication: To retrieve an authentication credential, first ask the relying party (aka the server) for ``PublicKeyCredentialRequestOptions``, then pass those to ``getAuthenticationCredential(options:minTimeout:maxTimeout:origin:assertAuthentication:)`` along with a closure that can validate credentials from configured ``AuthenticatorProtocol`` types such as ``KeyPairAuthenticator`` by passing the provided ``AssertionAuthentication`` to ``AuthenticatorProtocol/validateCredentials(with:)``, making sure to persist the resulting ``AuthenticatorProtocol/CredentialSource`` in some way. Finally, pass the resulting ``AuthenticationCredential`` back to the relying party to finish registration.
///
public struct WebAuthnClient {
    public init() {}
    
    public func createRegistrationCredential(
        options: PublicKeyCredentialCreationOptions,
        /// Recommended Range: https://w3c.github.io/webauthn/#recommended-range-and-default-for-a-webauthn-ceremony-timeout
        minTimeout: Duration = .seconds(300),
        maxTimeout: Duration = .seconds(600),
        origin: String,
        supportedPublicKeyCredentialParameters: Set<PublicKeyCredentialParameters> = .supported,
        attestRegistration: (_ registration: AttestationRegistrationRequest) async throws -> ()
    ) async throws -> RegistrationCredential {
        /// Steps: https://w3c.github.io/webauthn/#sctn-createCredential
        
        /// Step 1. Assert: options.publicKey is present.
        // Skip.
        
        /// Step 2. If sameOriginWithAncestors is false:
        ///     1. If the relevant global object, as determined by the calling create() implementation, does not have transient activation:
        ///         1. Throw a "NotAllowedError" DOMException.
        ///     2. Consume user activation of the relevant global object.
        // Skip.
        
        /// Step 3. Let pkOptions be the value of options.publicKey.
        // Skip.
        
        /// Step 4. If pkOptions.timeout is present, check if its value lies within a reasonable range as defined by the client and if not, correct it to the closest value lying within that range. Set a timer lifetimeTimer to this adjusted value. If pkOptions.timeout is not present, then set lifetimeTimer to a client-specific default.
        ///
        ///     See the recommended range and default for a WebAuthn ceremony timeout for guidance on deciding a reasonable range and default for pkOptions.timeout.
        let proposedTimeout = options.timeout ?? minTimeout
        let timeout = max(minTimeout, min(proposedTimeout, maxTimeout))
        
        /// Step 5. If the length of pkOptions.user.id is not between 1 and 64 bytes (inclusive) then throw a TypeError.
        guard 1...64 ~= options.user.id.count
        else { throw WebAuthnError.invalidUserID }
        
        /// Step 6. Let callerOrigin be origin. If callerOrigin is an opaque origin, throw a "NotAllowedError" DOMException.
        let callerOrigin = origin
        
        /// Step 7. Let effectiveDomain be the callerOrigin’s effective domain. If effective domain is not a valid domain, then throw a "SecurityError" DOMException.
        // Skip.
        
        /// Step 8. If pkOptions.rp.id
        ///     → is present
        ///         If pkOptions.rp.id is not a registrable domain suffix of and is not equal to effectiveDomain, throw a "SecurityError" DOMException.
        ///     → Is not present
        ///         Set pkOptions.rp.id to effectiveDomain.
        // Skip.
        
        /// Step 11. Let credTypesAndPubKeyAlgs be a new list whose items are pairs of PublicKeyCredentialType and a COSEAlgorithmIdentifier.
        var publicKeyCredentialParameters: [PublicKeyCredentialParameters] = []
        
        /// Step 12. If pkOptions.pubKeyCredParams’s size
        ///     → is zero
        ///         Append the following pairs of PublicKeyCredentialType and COSEAlgorithmIdentifier values to credTypesAndPubKeyAlgs:
        ///             public-key and -7 ("ES256").
        ///             public-key and -257 ("RS256").
        ///     → is non-zero
        ///         For each current of pkOptions.pubKeyCredParams:
        ///             1. If current.type does not contain a PublicKeyCredentialType supported by this implementation, then continue.
        ///             2. Let alg be current.alg.
        ///             3. Append the pair of current.type and alg to credTypesAndPubKeyAlgs.
        ///             If credTypesAndPubKeyAlgs is empty, throw a "NotSupportedError" DOMException.
        if options.publicKeyCredentialParameters.isEmpty {
            publicKeyCredentialParameters = [
                PublicKeyCredentialParameters(alg: .algES256),
//                PublicKeyCredentialParameters(alg: .algRS256),
            ]
        } else {
            for credentialParameter in options.publicKeyCredentialParameters {
                guard supportedPublicKeyCredentialParameters.contains(credentialParameter)
                else { continue }
                publicKeyCredentialParameters.append(credentialParameter)
            }
            guard !publicKeyCredentialParameters.isEmpty
            else { throw WebAuthnError.noSupportedCredentialParameters }
        }
        
        /// Step 15. Let clientExtensions be a new map and let authenticatorExtensions be a new map.
        // Skip.
        
        /// Step 16. If pkOptions.extensions is present, then for each extensionId → clientExtensionInput of pkOptions.extensions:
        ///     1. If extensionId is not supported by this client platform or is not a registration extension, then continue.
        ///     2. Set clientExtensions[extensionId] to clientExtensionInput.
        ///     3. If extensionId is not an authenticator extension, then continue.
        ///     4. Let authenticatorExtensionInput be the (CBOR) result of running extensionId’s client extension processing algorithm on clientExtensionInput. If the algorithm returned an error, continue.
        ///     5. Set authenticatorExtensions[extensionId] to the base64url encoding of authenticatorExtensionInput.
        // Skip.
        
        /// Step 17. Let collectedClientData be a new CollectedClientData instance whose fields are:
        let collectedClientData = CollectedClientData(
            /// type
            ///     The string "webauthn.create".
            type: .create,
            /// challenge
            ///     The base64url encoding of pkOptions.challenge.
            challenge: options.challenge.base64URLEncodedString(),
            /// origin
            ///     The serialization of callerOrigin.
            origin: callerOrigin
            /// topOrigin
            ///     The serialization of callerOrigin’s top-level origin if the sameOriginWithAncestors argument passed to this internal method is false, else undefined.
            // Skip.
            /// crossOrigin
            ///     The inverse of the value of the sameOriginWithAncestors argument passed to this internal method.
            // Skip.
        )
        
        /// Step 18. Let clientDataJSON be the JSON-compatible serialization of client data constructed from collectedClientData.
        let clientDataJSON = try JSONEncoder().encode(collectedClientData)
        
        /// Step 19. Let clientDataHash be the hash of the serialized client data represented by clientDataJSON.
        let clientDataHash = SHA256.hash(data: clientDataJSON)
        
        /// Step 20. If options.signal is present and aborted, throw the options.signal’s abort reason.
        // Skip.
        
        /// Step 21. Let issuedRequests be a new ordered set.
        // Skip.
        
        /// Step 22. Let authenticators represent a value which at any given instant is a set of client platform-specific handles, where each item identifies an authenticator presently available on this client platform at that instant.
        // Skip.
        
        /// Step 23. Consider the value of hints and craft the user interface accordingly, as the user-agent sees fit.
        // Skip.
        
        /// Step 24. Start lifetimeTimer.
        let timeoutTask = Task { try? await Task.sleep(for: timeout) }
        
        /// Step 25. While lifetimeTimer has not expired, perform the following actions depending upon lifetimeTimer, and the state and response for each authenticator in authenticators:
        do {
            /// Let the caller do what it needs to do to coordinate with authenticators, so long as at least one of them calls the attestation callback.
            var attestationObjectResult: AttestationObject = try await withCancellableFirstSuccessfulContinuation { [attestRegistration, publicKeyCredentialParameters] continuation in
                /// → If lifetimeTimer expires,
                ///     For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests.
                Task {
                    /// Let the timer run in the background to cancel the continuation if it runs over.
                    await timeoutTask.value
                    continuation.cancel() // TODO: Should be a timeout error
                }
                
                /// → If the user exercises a user agent user-interface option to cancel the process,
                ///     For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests. Throw a "NotAllowedError" DOMException.
                // Implemented in catch statement below.
                
                /// → If options.signal is present and aborted,
                ///     For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests. Then throw the options.signal’s abort reason.
                // Skip.
                
                ///     → If an authenticator becomes available on this client device,
                /// See ``KeyPairAuthenticator/makeCredentials(with:)`` for full implementation
                /// → If an authenticator ceases to be available on this client device,
                ///     Remove authenticator from issuedRequests.
                /// → If any authenticator returns a status indicating that the user cancelled the operation,
                ///     1. Remove authenticator from issuedRequests.
                ///     2. For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.
                ///         NOTE: Authenticators may return an indication of "the user cancelled the entire operation". How a user agent manifests this state to users is unspecified.
                // User can cancel the main task instead.
                
                /// → If any authenticator returns an error status equivalent to "InvalidStateError",
                ///     1. Remove authenticator from issuedRequests.
                ///     2. For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.
                ///     3. Throw an "InvalidStateError" DOMException.
                ///         NOTE: This error status is handled separately because the authenticator returns it only if excludeCredentialDescriptorList identifies a credential bound to the authenticator and the user has consented to the operation. Given this explicit consent, it is acceptable for this case to be distinguishable to the Relying Party.
                // TODO: Need to catch this specific type of error
                /// → If any authenticator returns an error status not equivalent to "InvalidStateError",
                ///         Remove authenticator from issuedRequests.
                ///         NOTE: This case does not imply user consent for the operation, so details about the error are hidden from the Relying Party in order to prevent leak of potentially identifying information. See § 14.5.1 Registration Ceremony Privacy for details.
                
                /// Kick off the attestation process, waiting for one to succeed before the timeout.
                try await attestRegistration(AttestationRegistrationRequest(
                    options: options,
                    publicKeyCredentialParameters: publicKeyCredentialParameters,
                    clientDataHash: clientDataHash
                ) { attestationObject in
                    continuation.resume(returning: attestationObject)
                })
            }
            
            ///     → If any authenticator indicates success,
            ///         1. Remove authenticator from issuedRequests. This authenticator is now the selected authenticator.
            ///         2. Let credentialCreationData be a struct whose items are:
            ///             attestationObjectResult
            ///                 whose value is the bytes returned from the successful authenticatorMakeCredential operation.
            ///                 NOTE: this value is attObj, as defined in § 6.5.4 Generating an Attestation Object.
            ///             clientDataJSONResult
            ///                 whose value is the bytes of clientDataJSON.
            ///             attestationConveyancePreferenceOption
            ///                 whose value is the value of pkOptions.attestation.
            ///             clientExtensionResults
            ///                 whose value is an AuthenticationExtensionsClientOutputs object containing extension identifier → client extension output entries. The entries are created by running each extension’s client extension processing algorithm to create the client extension outputs, for each client extension in pkOptions.extensions.
            ///         3. Let constructCredentialAlg be an algorithm that takes a global object global, and whose steps are:
            ///             1. If credentialCreationData.attestationConveyancePreferenceOption’s value is
            switch options.attestation {
                ///                 → none
            case .none:
                ///                 Replace potentially uniquely identifying information with non-identifying versions of the same:
                ///                     1. If the aaguid in the attested credential data is 16 zero bytes, credentialCreationData.attestationObjectResult.fmt is "packed", and "x5c" is absent from credentialCreationData.attestationObjectResult, then self attestation is being used and no further action is needed.
                ///                     2. Otherwise
                if attestationObjectResult.authenticatorData.attestedData?.authenticatorAttestationGUID != .anonymous,
                   attestationObjectResult.format != .packed,
                   attestationObjectResult.attestationStatement["x5c"] == nil {
                    ///                     1. Replace the aaguid in the attested credential data with 16 zero bytes.
                    attestationObjectResult.authenticatorData.attestedData?.authenticatorAttestationGUID = .anonymous
                    ///                     2. Set the value of credentialCreationData.attestationObjectResult.fmt to "none", and set the value of credentialCreationData.attestationObjectResult.attStmt to be an empty CBOR map. (See § 8.7 None Attestation Statement Format and § 6.5.4 Generating an Attestation Object).
                    attestationObjectResult.format = .none
                    attestationObjectResult.attestationStatement = [:]
                }
                ///                 → indirect
                ///                     The client MAY replace the aaguid and attestation statement with a more privacy-friendly and/or more easily verifiable version of the same data (for example, by employing an Anonymization CA).
                ///                 → direct or enterprise
                ///                     Convey the authenticator's AAGUID and attestation statement, unaltered, to the Relying Party.
            }
            ///         5. Let attestationObject be a new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of credentialCreationData.attestationObjectResult’s value.
            let attestationObject = attestationObjectResult.bytes
            
            ///         6. Let id be attestationObject.authData.attestedCredentialData.credentialId.
            guard let credentialID = attestationObjectResult.authenticatorData.attestedData?.credentialID
            else { throw WebAuthnError.attestedCredentialDataMissing }
            
            ///         7. Let pubKeyCred be a new PublicKeyCredential object associated with global whose fields are:
            let publicKeyCredential = RegistrationCredential(
                ///         [[identifier]]
                ///             id
                id: credentialID,
                ///         authenticatorAttachment
                ///             The AuthenticatorAttachment value matching the current authenticator attachment modality of authenticator.
                ///         response
                ///             A new AuthenticatorAttestationResponse object associated with global whose fields are:
                attestationResponse: AuthenticatorAttestationResponse(
                    ///             clientDataJSON
                    ///                 A new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of credentialCreationData.clientDataJSONResult.
                    clientDataJSON: Array(clientDataJSON),
                    ///             attestationObject
                    ///                 attestationObject
                    attestationObject: attestationObject
                    ///             [[transports]]
                    ///                 A sequence of zero or more unique DOMStrings, in lexicographical order, that the authenticator is believed to support. The values SHOULD be members of AuthenticatorTransport, but client platforms MUST ignore unknown values.
                    ///                 If a user agent does not wish to divulge this information it MAY substitute an arbitrary sequence designed to preserve privacy. This sequence MUST still be valid, i.e. lexicographically sorted and free of duplicates. For example, it may use the empty sequence. Either way, in this case the user agent takes the risk that Relying Party behavior may be suboptimal.
                    ///                 If the user agent does not have any transport information, it SHOULD set this field to the empty sequence.
                    ///                 NOTE: How user agents discover transports supported by a given authenticator is outside the scope of this specification, but may include information from an attestation certificate (for example [FIDO-Transports-Ext]), metadata communicated in an authenticator protocol such as CTAP2, or special-case knowledge about a platform authenticator.
                )
                ///         [[clientExtensionsResults]]
                ///             A new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of credentialCreationData.clientExtensionResults.
            )
            ///         8. Return pubKeyCred.
            // Returned below.
            
            ///     4. For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.
            // Already performed.
            
            ///     5. Return constructCredentialAlg and terminate this algorithm.
            return publicKeyCredential
        } catch {
            /// Step 35. Throw a "NotAllowedError" DOMException. In order to prevent information leak that could identify the user without consent, this step MUST NOT be executed before lifetimeTimer has expired. See § 14.5.1 Registration Ceremony Privacy for details.
            /// During the above process, the user agent SHOULD show some UI to the user to guide them in the process of selecting and authorizing an authenticator.
            await withTaskCancellationHandler {
                /// Make sure to wait until the timeout finishes if an error did occur.
                await timeoutTask.value
            } onCancel: {
                /// However, if the user cancelled the process, stop the timer early.
                timeoutTask.cancel()
            }
            /// Propagate the error originally thrown.
            throw error
        }
    }
    
    public func assertAuthenticationCredential(
        options: PublicKeyCredentialRequestOptions,
        /// Recommended Range: https://w3c.github.io/webauthn/#recommended-range-and-default-for-a-webauthn-ceremony-timeout
        minTimeout: Duration = .seconds(300),
        maxTimeout: Duration = .seconds(600),
        origin: String,
//        mediation: ,
        assertAuthentication: (_ authentication: AssertionAuthenticationRequest) async throws -> ()
    ) async throws -> AuthenticationCredential {
        /// See https://w3c.github.io/webauthn/#sctn-discover-from-external-source
        /// Step 1. Assert: options.publicKey is present.
        // Skip, already is.
        
        /// Step 2. Let pkOptions be the value of options.publicKey.
        // Skip, already is.
        
        /// Step 3. If options.mediation is present with the value conditional:
        ///     1. Let credentialIdFilter be the value of pkOptions.allowCredentials.
        ///     2. Set pkOptions.allowCredentials to empty.
        ///         NOTE: This prevents non-discoverable credentials from being used during conditional requests.
        ///     3. Set a timer lifetimeTimer to a value of infinity.
        ///         NOTE: lifetimeTimer is set to a value of infinity so that the user has the entire lifetime of the Document to interact with any input form control tagged with a "webauthn" autofill detail token. For example, upon the user clicking in such an input field, the user agent can render a list of discovered credentials for the user to select from, and perhaps also give the user the option to "try another way".
        // Skip.
        
        /// Step 4. Else:
        ///     1. Let credentialIdFilter be an empty list.
        // Skip.
        
        ///     2. If pkOptions.timeout is present, check if its value lies within a reasonable range as defined by the client and if not, correct it to the closest value lying within that range. Set a timer lifetimeTimer to this adjusted value. If pkOptions.timeout is not present, then set lifetimeTimer to a client-specific default.
        ///         See the recommended range and default for a WebAuthn ceremony timeout for guidance on deciding a reasonable range and default for pkOptions.timeout.
        ///         NOTE: The user agent should take cognitive guidelines into considerations regarding timeout for users with special needs.
        let proposedTimeout = options.timeout ?? minTimeout
        let timeout = max(minTimeout, min(proposedTimeout, maxTimeout))
        
        /// Step 5. Let callerOrigin be origin. If callerOrigin is an opaque origin, throw a "NotAllowedError" DOMException.
        let callerOrigin = origin
        
        /// Step 6. Let effectiveDomain be the callerOrigin’s effective domain. If effective domain is not a valid domain, then throw a "SecurityError" DOMException.
        ///     NOTE: An effective domain may resolve to a host, which can be represented in various manners, such as domain, ipv4 address, ipv6 address, opaque host, or empty host. Only the domain format of host is allowed here. This is for simplification and also is in recognition of various issues with using direct IP address identification in concert with PKI-based security.
        // Skip.
        
        /// Step 7. If pkOptions.rpId is not present, then set rpId to effectiveDomain.
        ///     Otherwise:
        ///         1. If pkOptions.rpId is not a registrable domain suffix of and is not equal to effectiveDomain, throw a "SecurityError" DOMException.
        ///         2. Set rpId to pkOptions.rpId.
        ///             NOTE: rpId represents the caller’s RP ID. The RP ID defaults to being the caller’s origin's effective domain unless the caller has explicitly set pkOptions.rpId when calling get().
        // Skip.
        
        /// Step 8. Let clientExtensions be a new map and let authenticatorExtensions be a new map.
        // Skip.
        
        /// Step 9. If pkOptions.extensions is present, then for each extensionId → clientExtensionInput of pkOptions.extensions:
        ///     1. If extensionId is not supported by this client platform or is not an authentication extension, then continue.
        ///     2. Set clientExtensions[extensionId] to clientExtensionInput.
        ///     3. If extensionId is not an authenticator extension, then continue.
        ///     4. Let authenticatorExtensionInput be the (CBOR) result of running extensionId’s client extension processing algorithm on clientExtensionInput. If the algorithm returned an error, continue.
        ///     5. Set authenticatorExtensions[extensionId] to the base64url encoding of authenticatorExtensionInput.
        // Skip.
        
        /// Step 10. Let collectedClientData be a new CollectedClientData instance whose fields are:
        let collectedClientData = CollectedClientData(
            /// type
            ///     The string "webauthn.get".
            type: .assert,
            /// challenge
            ///     The base64url encoding of pkOptions.challenge
            challenge: options.challenge.base64URLEncodedString(),
            /// origin
            ///     The serialization of callerOrigin.
            origin: callerOrigin
            /// topOrigin
            ///     The serialization of callerOrigin’s top-level origin if the sameOriginWithAncestors argument passed to this internal method is false, else undefined.
            // Skip.
            /// crossOrigin
            ///     The inverse of the value of the sameOriginWithAncestors argument passed to this internal method.
            // Skip.
        )
        
        /// Step 11. Let clientDataJSON be the JSON-compatible serialization of client data constructed from collectedClientData.
        let clientDataJSON = try JSONEncoder().encode(collectedClientData)
        
        /// Step 12. Let clientDataHash be the hash of the serialized client data represented by clientDataJSON.
        let clientDataHash = SHA256.hash(data: clientDataJSON)
        
        /// Step 13. If options.signal is present and aborted, throw the options.signal’s abort reason.
        // Skip.
        
        /// Step 14. Let issuedRequests be a new ordered set.
        // Skip.
        
        /// Step 15. Let savedCredentialIds be a new map.
        // Skip.
        
        /// Step 16. Let authenticators represent a value which at any given instant is a set of client platform-specific handles, where each item identifies an authenticator presently available on this client platform at that instant.
        ///     NOTE: What qualifies an authenticator as "available" is intentionally unspecified; this is meant to represent how authenticators can be hot-plugged into (e.g., via USB) or discovered (e.g., via NFC or Bluetooth) by the client by various mechanisms, or permanently built into the client.
        // Skip.
        
        /// Step 17. Let silentlyDiscoveredCredentials be a new map whose entries are of the form: DiscoverableCredentialMetadata → authenticator.
        // Skip.
        
        /// Step 18. Consider the value of hints and craft the user interface accordingly, as the user-agent sees fit.
        // Skip.
        
        /// Step 19. Start lifetimeTimer.
        let timeoutTask = Task { try? await Task.sleep(for: timeout) }
        
        /// Step 20. While lifetimeTimer has not expired, perform the following actions depending upon lifetimeTimer, and the state and response for each authenticator in authenticators:
        do {
            /// Let the caller do what it needs to do to coordinate with authenticators, so long as at least one of them calls the assertion callback.
            let assertionResults: AssertionAuthenticationRequest.Results = try await withCancellableFirstSuccessfulContinuation { [assertAuthentication] continuation in
                /// → If lifetimeTimer expires,
                ///     For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests.
                Task {
                    /// Let the timer run in the background to cancel the continuation if it runs over.
                    await timeoutTask.value
                    continuation.cancel() // TODO: Should be a timeout error
                }
                
                /// → If the user exercises a user agent user-interface option to cancel the process,
                ///     For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests. Throw a "NotAllowedError" DOMException.
                // Skip.
                
                /// → If options.signal is present and aborted,
                ///     For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests. Then throw the options.signal’s abort reason.
                // Skip.
                
                /// → If options.mediation is conditional and the user interacts with an input or textarea form control with an autocomplete attribute whose non-autofill credential type is "webauthn",
                ///     Note: The "webauthn" autofill detail token must appear immediately after the last autofill detail token of type "Normal" or "Contact". For example:
                ///         "username webauthn"
                ///         "current-password webauthn"
                ///     1. If silentlyDiscoveredCredentials is not empty:
                ///         1. Prompt the user to optionally select a DiscoverableCredentialMetadata (credentialMetadata) from silentlyDiscoveredCredentials.
                ///             NOTE: The prompt shown SHOULD include values from credentialMetadata’s otherUI such as name and displayName.
                ///         2. If the user selects a credentialMetadata,
                ///             1. Let publicKeyOptions be a temporary copy of pkOptions.
                ///             2. Let authenticator be the value of silentlyDiscoveredCredentials[credentialMetadata].
                ///             3. Set publicKeyOptions.allowCredentials to be a list containing a single PublicKeyCredentialDescriptor item whose id's value is set to credentialMetadata’s id's value and whoseid value is set to credentialMetadata’s type.
                ///             4. Execute the issuing a credential request to an authenticator algorithm with authenticator, savedCredentialIds, publicKeyOptions, rpId, clientDataHash, and authenticatorExtensions.
                ///                 If this returns false, continue.
                ///             5. Append authenticator to issuedRequests.
                // Skip.
                
                /// → If options.mediation is not conditional, issuedRequests is empty, pkOptions.allowCredentials is not empty, and no authenticator will become available for any public key credentials therein,
                ///     Indicate to the user that no eligible credential could be found. When the user acknowledges the dialog, throw a "NotAllowedError" DOMException.
                ///     NOTE: One way a client platform can determine that no authenticator will become available is by examining the transports members of the present PublicKeyCredentialDescriptor items of pkOptions.allowCredentials, if any. For example, if all PublicKeyCredentialDescriptor items list only internal, but all platform authenticators have been tried, then there is no possibility of satisfying the request. Alternatively, all PublicKeyCredentialDescriptor items may list transports that the client platform does not support.
                // Skip.
                
                /// → If an authenticator becomes available on this client device,
                ///     NOTE: This includes the case where an authenticator was available upon lifetimeTimer initiation.
                ///     1. If options.mediation is conditional and the authenticator supports the silentCredentialDiscovery operation:
                ///         1. Let collectedDiscoveredCredentialMetadata be the result of invoking the silentCredentialDiscovery operation on authenticator with rpId as parameter.
                ///         2. For each credentialMetadata of collectedDiscoveredCredentialMetadata:
                ///             1. If credentialIdFilter is empty or credentialIdFilter contains an item whose id's value is set to credentialMetadata’s id, set silentlyDiscoveredCredentials[credentialMetadata] to authenticator.
                ///                 NOTE: A request will be issued to this authenticator upon user selection of a credential via interaction with a particular UI context (see here for details).
                // Skip.
                
                ///     2. Else:
                ///         1. Execute the issuing a credential request to an authenticator algorithm with authenticator, savedCredentialIds, pkOptions, rpId, clientDataHash, and authenticatorExtensions.
                ///             If this returns false, continue.
                ///             NOTE: This branch is taken if options.mediation is conditional and the authenticator does not support the silentCredentialDiscovery operation to allow use of such authenticators during a conditional user mediation request.
                ///         2. Append authenticator to issuedRequests.
                try await assertAuthentication(AssertionAuthenticationRequest(
                    options: options,
                    clientDataHash: clientDataHash,
                    attemptAuthentication: { assertionResults in
                        continuation.resume(returning: assertionResults)
                    }
                ))
            }
            
            /// → If an authenticator ceases to be available on this client device,
            ///     Remove authenticator from issuedRequests.
            // Skip.
            
            /// → If any authenticator returns a status indicating that the user cancelled the operation,
            ///     1. Remove authenticator from issuedRequests.
            ///     2. For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.
            ///         NOTE: Authenticators may return an indication of "the user cancelled the entire operation". How a user agent manifests this state to users is unspecified.
            // Skip.
            
            /// → If any authenticator returns an error status,
            ///     Remove authenticator from issuedRequests.
            // Skip.
            
            /// → If any authenticator indicates success,
            ///     1. Remove authenticator from issuedRequests.
            ///     2. Let assertionCreationData be a struct whose items are:
            ///         credentialIdResult
            ///             If savedCredentialIds[authenticator] exists, set the value of credentialIdResult to be the bytes of savedCredentialIds[authenticator]. Otherwise, set the value of credentialIdResult to be the bytes of the credential ID returned from the successful authenticatorGetAssertion operation, as defined in § 6.3.3 The authenticatorGetAssertion Operation.
            ///         clientDataJSONResult
            ///             whose value is the bytes of clientDataJSON.
            ///         authenticatorDataResult
            ///             whose value is the bytes of the authenticator data returned by the authenticator.
            ///         signatureResult
            ///             whose value is the bytes of the signature value returned by the authenticator.
            ///         userHandleResult
            ///             If the authenticator returned a user handle, set the value of userHandleResult to be the bytes of the returned user handle. Otherwise, set the value of userHandleResult to null.
            ///         clientExtensionResults
            ///             whose value is an AuthenticationExtensionsClientOutputs object containing extension identifier → client extension output entries. The entries are created by running each extension’s client extension processing algorithm to create the client extension outputs, for each client extension in pkOptions.
            // Already created above.
            
            ///     3. If credentialIdFilter is not empty and credentialIdFilter does not contain an item whose id's value is set to the value of credentialIdResult, continue.
            // SKip.
            
            ///     4. If credentialIdFilter is empty and userHandleResult is null, continue.
            // SKip.
            
            ///     5. Let constructAssertionAlg be an algorithm that takes a global object global, and whose steps are:
            ///         1. Let pubKeyCred be a new PublicKeyCredential object associated with global whose fields are:
            let publicKeyCredential = AuthenticationCredential(
                ///         [[identifier]]
                ///             A new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of assertionCreationData.credentialIdResult.
                id: assertionResults.credentialID,
                ///         authenticatorAttachment
                ///             The AuthenticatorAttachment value matching the current authenticator attachment modality of authenticator.
                authenticatorAttachment: assertionResults.authenticatorAttachment,
                ///         response
                ///             A new AuthenticatorAssertionResponse object associated with global whose fields are:
                response: AuthenticatorAssertionResponse(
                    ///             clientDataJSON
                    ///                 A new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of assertionCreationData.clientDataJSONResult.
                    clientDataJSON: Array(clientDataJSON),
                    ///             authenticatorData
                    ///                 A new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of assertionCreationData.authenticatorDataResult.
                    authenticatorData: assertionResults.authenticatorData,
                    ///             signature
                    ///                 A new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of assertionCreationData.signatureResult.
                    signature: assertionResults.signature,
                    ///             userHandle
                    ///                 If assertionCreationData.userHandleResult is null, set this field to null. Otherwise, set this field to a new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of assertionCreationData.userHandleResult.
                    userHandle: assertionResults.userHandle,
                    attestationObject: nil
                )
                ///         [[clientExtensionsResults]]
                ///                 A new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of assertionCreationData.clientExtensionResults.
                // Skip.
            )
            ///         2. Return pubKeyCred.
            // Returned below.
            
            ///     6. For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.
            // Already performed.
            
            ///     7. Return constructAssertionAlg and terminate this algorithm.
            return publicKeyCredential
        } catch {
            /// Step 31. Throw a "NotAllowedError" DOMException. In order to prevent information leak that could identify the user without consent, this step MUST NOT be executed before lifetimeTimer has expired. See § 14.5.2 Authentication Ceremony Privacy for details.
            await withTaskCancellationHandler {
                /// Make sure to wait until the timeout finishes if an error did occur.
                await timeoutTask.value
            } onCancel: {
                /// However, if the user cancelled the process, stop the timer early.
                timeoutTask.cancel()
            }
            /// Propagate the error originally thrown.
            throw error
        }
    }
}

// MARK: Convenience Registration and Authentication

extension WebAuthnClient {
    @inlinable
    public func createRegistrationCredential<Authenticator: AuthenticatorProtocol & Sendable>(
        options: PublicKeyCredentialCreationOptions,
        /// Recommended Range: https://w3c.github.io/webauthn/#recommended-range-and-default-for-a-webauthn-ceremony-timeout
        minTimeout: Duration = .seconds(300),
        maxTimeout: Duration = .seconds(600),
        origin: String,
        supportedPublicKeyCredentialParameters: Set<PublicKeyCredentialParameters> = .supported,
        authenticator: Authenticator
    ) async throws -> (registrationCredential: RegistrationCredential, credentialSource: Authenticator.CredentialSource) {
        var credentialSource: Authenticator.CredentialSource?
        let registrationCredential = try await createRegistrationCredential(
            options: options,
            minTimeout: minTimeout,
            maxTimeout: maxTimeout,
            origin: origin,
            supportedPublicKeyCredentialParameters: supportedPublicKeyCredentialParameters
        ) { registration in
            credentialSource = try await authenticator.makeCredentials(with: registration)
        }
        
        guard let credentialSource
        else { throw WebAuthnError.missingCredentialSourceDespiteSuccess }
        
        return (registrationCredential, credentialSource)
    }
    
    @inlinable
    public func createRegistrationCredential<each Authenticator: AuthenticatorProtocol & Sendable>(
        options: PublicKeyCredentialCreationOptions,
        /// Recommended Range: https://w3c.github.io/webauthn/#recommended-range-and-default-for-a-webauthn-ceremony-timeout
        minTimeout: Duration = .seconds(300),
        maxTimeout: Duration = .seconds(600),
        origin: String,
        supportedPublicKeyCredentialParameters: Set<PublicKeyCredentialParameters> = .supported,
        authenticators: repeat each Authenticator
    ) async throws -> (
        registrationCredential: RegistrationCredential,
        credentialSources: (repeat Result<(each Authenticator).CredentialSource, Error>)
    ) {
        /// Wrapper function since `repeat` doesn't currently support complex expressions
        @Sendable func register<LocalAuthenticator: AuthenticatorProtocol & Sendable>(
            authenticator: LocalAuthenticator,
            registration: AttestationRegistrationRequest
        ) -> Task<LocalAuthenticator.CredentialSource, Error> {
            Task { try await authenticator.makeCredentials(with: registration) }
        }
        
        var credentialSources: (repeat Result<(each Authenticator).CredentialSource, Error>)?
        let registrationCredential = try await createRegistrationCredential(
            options: options,
            minTimeout: minTimeout,
            maxTimeout: maxTimeout,
            origin: origin,
            supportedPublicKeyCredentialParameters: supportedPublicKeyCredentialParameters
        ) { registration in
            /// Run each authenticator in parallel as child tasks, so we can automatically propagate cancellation to each of them should it occur.
            let tasks = (repeat register(
                authenticator: each authenticators,
                registration: registration
            ))
            await withTaskCancellationHandler {
                credentialSources = (repeat await (each tasks).result)
            } onCancel: {
                repeat (each tasks).cancel()
            }
        }
        
        guard let credentialSources
        else { throw WebAuthnError.missingCredentialSourceDespiteSuccess }
        
        return (registrationCredential, credentialSources)
    }
    
    @inlinable
    public func assertAuthenticationCredential<Authenticator: AuthenticatorProtocol>(
        options: PublicKeyCredentialRequestOptions,
        /// Recommended Range: https://w3c.github.io/webauthn/#recommended-range-and-default-for-a-webauthn-ceremony-timeout
        minTimeout: Duration = .seconds(300),
        maxTimeout: Duration = .seconds(600),
        origin: String,
//        mediation: ,
        authenticator: Authenticator,
        credentialStore: CredentialStore<Authenticator>
    ) async throws -> (
        authenticationCredential: AuthenticationCredential,
        updatedCredentialSource: Authenticator.CredentialSource
    ) {
        var credentialSource: Authenticator.CredentialSource?
        let authenticationCredential = try await assertAuthenticationCredential(
            options: options,
            minTimeout: minTimeout,
            maxTimeout: maxTimeout,
            origin: origin
        ) { authentication in
            credentialSource = try await authenticator.assertCredentials(
                authenticationRequest: authentication,
                credentials: credentialStore
            )
        }
        
        guard let credentialSource
        else { throw WebAuthnError.missingCredentialSourceDespiteSuccess }
        
        return (authenticationCredential, credentialSource)
    }
    
    @inlinable
    public func assertAuthenticationCredential<each Authenticator: AuthenticatorProtocol & Sendable>(
        options: PublicKeyCredentialRequestOptions,
        /// Recommended Range: https://w3c.github.io/webauthn/#recommended-range-and-default-for-a-webauthn-ceremony-timeout
        minTimeout: Duration = .seconds(300),
        maxTimeout: Duration = .seconds(600),
        origin: String,
//        mediation: ,
        authenticators: repeat each Authenticator,
        credentialStores: repeat CredentialStore<(each Authenticator)>
    ) async throws -> (
        authenticationCredential: AuthenticationCredential,
        updatedCredentialSources: (repeat Result<(each Authenticator).CredentialSource, Error>)
    ) {
        /// Wrapper function since `repeat` doesn't currently support complex expressions
        @Sendable func authenticate<LocalAuthenticator: AuthenticatorProtocol & Sendable>(
            authenticator: LocalAuthenticator,
            authentication: AssertionAuthenticationRequest,
            credentials: CredentialStore<LocalAuthenticator>
        ) -> Task<LocalAuthenticator.CredentialSource, Error> {
            Task {
                try await authenticator.assertCredentials(
                    authenticationRequest: authentication,
                    credentials: credentials
                )
            }
        }
        
        var credentialSources: (repeat Result<(each Authenticator).CredentialSource, Error>)?
        let authenticationCredential = try await assertAuthenticationCredential(
            options: options,
            minTimeout: minTimeout,
            maxTimeout: maxTimeout,
            origin: origin
        ) { authentication in
            /// Run each authenticator in parallel as child tasks, so we can automatically propagate cancellation to each of them should it occur.
            let tasks = (repeat authenticate(
                authenticator: each authenticators,
                authentication: authentication,
                credentials: each credentialStores
            ))
            await withTaskCancellationHandler {
                credentialSources = (repeat await (each tasks).result)
            } onCancel: {
                repeat (each tasks).cancel()
            }
        }
        
        guard let credentialSources
        else { throw WebAuthnError.missingCredentialSourceDespiteSuccess }
        
        return (authenticationCredential, credentialSources)
    }
}
