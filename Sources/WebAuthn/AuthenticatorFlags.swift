struct AuthenticatorFlags {
    
    /**
     Taken from https://w3c.github.io/webauthn/#sctn-authenticator-data
     Bit 0: User Present Result
     Bit 1: Reserved for future use
     Bit 2: User Verified Result
     Bits 3-5: Reserved for future use
     Bit 6: Attested credential data included
     Bit 7: Extension data include
     */
    
    enum Bit: UInt8 {
        case userPresent = 0
        case userVerified = 2
        case attestedCredentialDataIncluded = 6
        case extensionDataIncluded = 7
    }
    
    let userPresent: Bool
    let userVerified: Bool
    let attestedCredentialData: Bool
    let extensionDataIncluded: Bool
    
    init(_ byte: UInt8) {
        userPresent = Self.isFlagSet(on: byte, at: .userPresent)
        userVerified = Self.isFlagSet(on: byte, at: .userVerified)
        attestedCredentialData = Self.isFlagSet(on: byte, at: .attestedCredentialDataIncluded)
        extensionDataIncluded = Self.isFlagSet(on: byte, at: .extensionDataIncluded)
    }
    
    static func isFlagSet(on byte: UInt8, at position: Bit) -> Bool {
        (byte & (1 << position.rawValue)) != 0
    }
}
