import Crypto

/// AuthenticatorData From §6.1 of the spec.
///
/// The authenticator data structure encodes contextual bindings made by the authenticator. These bindings
/// are controlled by the authenticator itself, and derive their trust from the WebAuthn Relying Party's
/// assessment of the security properties of the authenticator. In one extreme case, the authenticator
/// may be embedded in the client, and its bindings may be no more trustworthy than the client data.
/// At the other extreme, the authenticator may be a discrete entity with high-security hardware and
/// software, connected to the client over a secure channel. In both cases, the Relying Party receives
/// the authenticator data in the same format, and uses its knowledge of the authenticator to make
/// trust decisions.
///
/// The authenticator data, at least during attestation, contains the Public Key that the RP stores
/// and will associate with the user attempting to register.
struct AuthenticatorData {
    let relyingPartyIDHash: [UInt8]
    let flags: AuthenticatorFlags
    let counter: UInt32
    /// For attestation signatures this value will be set. For assertion signatures not.
    let attestedData: AttestedCredentialData?
    let extData: [UInt8]?
}