# webauthn-swift

This package provides a Swift implementation of the [WebAuthn API](https://w3c.github.io/webauthn) focused on making it
easy to leverage the power of WebAuthn.

🚨 This library is a proof of concept - do not use it in production yet!

## Documentation

Documentation and how-to-guides can be found in our DocC documentation, hosted by [Swift Package Index](https://swiftpackageindex.com/):

[https://swiftpackageindex.com/swift-server/webauthn-swift/main/documentation/webauthn](https://swiftpackageindex.com/swift-server/webauthn-swift/main/documentation/webauthn)

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

### Setup

Configure your Relying Party with a `WebAuthnManager` instance:

```swift
let webAuthnManager = WebAuthnManager(
    config: WebAuthnConfig(
        relyingPartyDisplayName: "My Fancy Web App",
        relyingPartyID: "example.com",
        relyingPartyOrigin: "https://example.com",
        timeout: 600
    )
)
```

### Registration

For a registration ceremony use the following two methods:

- `WebAuthnManager.beginRegistration()`
- `WebAuthnManager.finishRegistration()`

### Authentication

For an authentication ceremony use the following two methods:

- `WebAuthnManager.beginAuthentication()`
- `WebAuthnManager.finishAuthentication()`

## Credits

Swift WebAuthn is heavily inspired by existing WebAuthn libraries like
[py_webauthn](https://github.com/duo-labs/py_webauthn) and [go-webauthn](https://github.com/go-webauthn/webauthn).

## Links

- [WebAuthn.io](https://webauthn.io/)
- [WebAuthn guide](https://webauthn.guide/)
- [WebAuthn Spec](https://w3c.github.io/webauthn/)
- [CBOR.me](https://cbor.me/)
