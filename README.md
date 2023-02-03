# webauthn-swift

This package provides a Swift implementation of the [WebAuthn API](https://w3c.github.io/webauthn) focused on making it
easy to leverage the power of WebAuthn.

🚨 This library is a proof of concept - do not use it in production yet!

## Getting Started

**Adding the dependency**

Add the following entry in your `Package.swift` to start using `WebAuthn`:

```swift
.package(url: "https://github.com/swift-server/webauthn-swift.git", branch: "main")
```

and `WebAuthn` dependency to your target:

```swift
.target(name: "MyApp", dependencies: [.product(name: "WebAuthn", package: "webauthn-swift")])
```

## Usage

The library exposes just four core methods through the `WebAuthnManager` struct:

- `WebAuthnManager.beginRegistration()`
- `WebAuthnManager.finishRegistration()`
- `WebAuthnManager.beginAuthentication()`
- `WebAuthnManager.finishAuthentication()`

Generally, the library makes the following assumptions about how a Relying Party implementing this library will
interface with a webpage that will handle calling the WebAuthn API:

1. JSON is the preferred data type for transmitting registration and authentication options from the server to
   the webpage to feed to `navigator.credentials.create()` and `navigator.credentials.get()` respectively.

2. JSON is the preferred data type for transmitting WebAuthn responses from the browser to the Relying Party.

3. Bytes are not directly transmittable in either direction as JSON, and so should be encoded to and decoded
   from base64url. To make life a little bit easier there are two typealiases indicating whether something is expected,
   or returned, as base64/base64url:

   - `public typealias URLEncodedBase64 = String`
   - `public typealias EncodedBase64 = String`

### Example flow:

#### Setup


#### Registration

1. A user wants to signup on a website using WebAuthn. The client makes a request to the backend which implements this
   library. On request the backend calls the `beginRegistration(user:)` method and sends the returned
   `PublicKeyCredentialCreationOptions` back to the client.

2. The client passes the received `PublicKeyCredentialCreationOptions` via the WebAuthn API to
   `navigator.credentials.create()`. This in turn will prompt the user to create a new credential using an
   authenticator of their choice (TouchID, security keys, ...). The response must then be send back to the backend.

3. On request the backend calls the `finishRegistration(challenge:credentialCreationData:)` method with the previously
   generated challenge and the received authenticator response (from `navigator.credentials.create()`). If
   `finishRegistration` succeeds a new `Credential` object will be returned. This object should be persisted somewhere
   (e.g. a database) and linked to the user from step 1.

#### Authentication

1. A user wants to log in on a website using WebAuthn. When tapping the "Login" button the client send a request to
   the backend. The backend responds to this request with a call to `beginAuthentication()` which then in turn
   returns a new `PublicKeyCredentialRequestOptions`. This must be send back to the client so it can pass it to
   `navigator.credentials.get()`.
2. Whatever `navigator.credentials.get()` returns will be send back to the backend, parsing it into
   `AuthenticationCredential`.
   ```swift
   let authenticationCredential = try req.content.decode(AuthenticationCredential.self)
   ```
3. Next the backend calls
   `finishAuthentication(credential:expectedChallenge:credentialPublicKey:credentialCurrentSignCount:)`.
    - The `credential` parameter expects the decoded `AuthenticationCredential`
    - The `expectedChallenge` parameter expects the challenge previously generated
      from `beginAuthentication()` (e.g. through a session).
    - Query the persisted credential from [Registration](####registration) using the credential id from the decoded
      `AuthenticationCredential`. Pass this credential in the `credentialPublicKey` parameter and it's sign count to
      `credentialCurrentSignCount`.

4. If `finishAuthentication` succeeds you can safely login the user linked to the credential! `finishAuthentication`
   will return a `VerifiedAuthentication` with the updated sign count and a few other information. Use this to
   update the credential in the database.