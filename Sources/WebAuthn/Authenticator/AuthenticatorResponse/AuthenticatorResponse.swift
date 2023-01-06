//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2022 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// From §5.2 (https://w3c.github.io/webauthn/#iface-authenticatorresponse)
/// Authenticators respond to Relying Party requests by returning an object derived from the
/// AuthenticatorResponse interface
public protocol AuthenticatorResponse {
    var clientDataJSON: URLEncodedBase64 { get }
}
