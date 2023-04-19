# Example Implementation

Explains how to use this library in a server <-> website scenario.

The library exposes four methods through ``WebAuthnManager``:

- ``WebAuthnManager/beginRegistration(user:timeout:attestation:publicKeyCredentialParameters:)``
- ``WebAuthnManager/finishRegistration(challenge:credentialCreationData:requireUserVerification:supportedPublicKeyAlgorithms:pemRootCertificatesByFormat:confirmCredentialIDNotRegisteredYet:)``
- ``WebAuthnManager/beginAuthentication(challenge:timeout:allowCredentials:userVerification:)``
- ``WebAuthnManager/finishAuthentication(credential:expectedChallenge:credentialPublicKey:credentialCurrentSignCount:requireUserVerification:)``

Generally, the library makes the following assumptions about how a Relying Party implementing this library will
interface with a client that will handle calling the WebAuthn API:

1. JSON is the preferred data type for transmitting registration and authentication options from the server to
   the client to feed to `navigator.credentials.create()` and `navigator.credentials.get()` respectively.

2. JSON is the preferred data type for transmitting WebAuthn responses from the client to the Relying Party.

3. Bytes are not directly transmittable in either direction as JSON, and so should be encoded to and decoded
   using Base64 URL encoding. To make life a little bit easier ``URLEncodedBase64`` and ``EncodedBase64`` indicate whether a `String` is currently encoded or not.

## Limitations

There are a few things this library currently does **not** support:

1. Currently RSA public keys are not support, we do however plan to add support for that. RSA keys are necessary for
   compatibility with Microsoft Windows platform authenticators.

2. Octet key pairs are not supported.

3. Attestation verification is currently not supported, we do however plan to add support for that. Some work has been
   done already, but there are more pieces missing. In most cases attestation verification is not recommended since it
   causes a lot of overhead. [From Yubico](https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/Attestation.html):
   > "If a service does not have a specific need for attestation information, namely a well defined policy for what to
     do with it and why, it is not recommended to verify authenticator attestations"

### Setup

Configure your backend with a ``WebAuthnManager`` instance:

```swift
app.webAuthn = WebAuthnManager(
    config: WebAuthnConfig(
        relyingPartyDisplayName: "My Fancy Web App",
        relyingPartyID: "example.com",
        relyingPartyOrigin: "https://example.com",
        timeout: 600
    )
)
```

### Registration

Scenario: A user wants to signup on a website using WebAuthn.

![Registration flow overview](registration.svg)

#### Explanation

1. When tapping the "Register" button the client sends a request to
   the backend. The backend responds to this request with a call to `begingRegistration(user:)` which then returns a
   new ``PublicKeyCredentialRequestOptions``. This must be send back to the client so it can pass it to
   `navigator.credentials.create()`.

2. Whatever `navigator.credentials.create()` returns will be send back to the backend, parsing it into
   ``RegistrationCredential``.
    ```swift
    let registrationCredential = try req.content.decode(RegistrationCredential.self)
    ```

3. Next the backend calls `finishRegistration(challenge:credentialCreationData:)` with the previously
   generated challenge and the received ``RegistrationCredential``. If `finishRegistration` succeeds a new ``Credential``
   object will be returned. This object contains information about the new credential, including an id and the generated public-key. Persist this data in e.g. a database and link the entry to the user.

##### Example implementation (using Vapor)

```swift
authSessionRoutes.get("makeCredential") { req -> PublicKeyCredentialCreationOptions in
    let user = try req.auth.require(User.self)
    let options = try req.webAuthn.beginRegistration(user: user)
    req.session.data["challenge"] = options.challenge
    return options
}

authSessionRoutes.post("makeCredential") { req -> HTTPStatus in
    let user = try req.auth.require(User.self)
    guard let challenge = req.session.data["challenge"] else { throw Abort(.unauthorized) }
    let registrationCredential = try req.content.decode(RegistrationCredential.self)

    let credential = try await req.webAuthn.finishRegistration(
        challenge: challenge,
        credentialCreationData: registrationCredential,
        // this is likely to be removed soon
        confirmCredentialIDNotRegisteredYet: { credentialID in
            try await queryCredentialWithUser(id: credentialID) == nil
        }
    )

    try await WebAuthnCredential(from: credential, userID: user.requireID())
        .save(on: req.db)

    return .ok
}
```

### Authentication

Scenario: A user wants to log in on a website using WebAuthn.

![Authentication flow overview](authentication.svg)

#### Explanation

1. When tapping the "Login" button the client sends a request to
   the backend. The backend responds to this request with a call to `beginAuthentication()` which then in turn
   returns a new ``PublicKeyCredentialRequestOptions``. This must be sent back to the client so it can pass it to
   `navigator.credentials.get()`.
2. Whatever `navigator.credentials.get()` returns will be sent back to the backend, parsing it into
   ``AuthenticationCredential``.
   ```swift
   let authenticationCredential = try req.content.decode(AuthenticationCredential.self)
   ```
3. Next the backend calls
   ``WebAuthnManager/finishAuthentication(credential:expectedChallenge:credentialPublicKey:credentialCurrentSignCount:requireUserVerification:)``.
    - The `credential` parameter expects the decoded ``AuthenticationCredential``
    - The `expectedChallenge` parameter expects the challenge previously generated
      from `beginAuthentication()` (obtained e.g. through a session).
    - Query the persisted credential from [Registration](#registration) using the credential id from the decoded
      `AuthenticationCredential`. Pass this credential in the `credentialPublicKey` parameter and it's sign count to
      `credentialCurrentSignCount`.

4. If `finishAuthentication` succeeds you can safely login the user linked to the credential! `finishAuthentication`
   will return a `VerifiedAuthentication` with the updated sign count and a few other pieces of information to be
   persisted. Use this to update the credential in the database.

#### Example implementation

```swift
// this endpoint will be called on clicking "Login"
authSessionRoutes.get("authenticate") { req -> PublicKeyCredentialRequestOptions in
    let options = try req.webAuthn.beginAuthentication()
    req.session.data["challenge"] = String.base64URL(fromBase64: options.challenge)
    return options
}

// this endpoint will be called after the user used e.g. TouchID.
authSessionRoutes.post("authenticate") { req -> HTTPStatus in
    guard let challenge = req.session.data["challenge"] else { throw Abort(.unauthorized) }
    let data = try req.content.decode(AuthenticationCredential.self)
    guard let credential = try await queryCredentialWithUser(id: data.id) else {
        throw Abort(.unauthorized)
    }

    let verifiedAuthentication = try req.webAuthn.finishAuthentication(
        credential: data,
        expectedChallenge: challenge,
        credentialPublicKey: [UInt8](credential.publicKey.base64URLDecodedData!),
        credentialCurrentSignCount: 0
    )

    req.auth.login(credential.user)

    return .ok
}
```