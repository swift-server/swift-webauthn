# swift-webauthn

This package provides a Swift implementation of the [WebAuthn API](https://w3c.github.io/webauthn) focused on making it
easy to leverage the power of WebAuthn to support Passkeys and security keys.

## Getting Started

**Adding the dependency**

Add the following entry in your `Package.swift` to start using `WebAuthn`:

```swift
.package(url: "https://github.com/swift-server/swift-webauthn.git", from: "1.0.0-alpha.2")
```

and `WebAuthn` dependency to your target:

```swift
.target(name: "MyApp", dependencies: [.product(name: "WebAuthn", package: "swift-webauthn")])
```

### Setup

Configure your Relying Party with a `WebAuthnManager` instance:

```swift
let webAuthnManager = WebAuthnManager(
    configuration: WebAuthnManager.Configuration(
        relyingPartyID: "example.com",
        relyingPartyName: "My Fancy Web App",
        relyingPartyOrigin: "https://example.com"
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

## Contributing

If you add any new files, please run the following command at the root of the repo to identify any missing license headers:
```bash
% PROJECTNAME="Swift WebAuthn" /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/swiftlang/github-workflows/refs/heads/main/.github/workflows/scripts/check-license-header.sh)"
```

## Credits

Swift WebAuthn is heavily inspired by existing WebAuthn libraries like
[py_webauthn](https://github.com/duo-labs/py_webauthn) and [go-webauthn](https://github.com/go-webauthn/webauthn).

## Links

- [WebAuthn.io](https://webauthn.io/)
- [WebAuthn guide](https://webauthn.guide/)
- [WebAuthn Spec](https://w3c.github.io/webauthn/)
- [CBOR.me](https://cbor.me/)
