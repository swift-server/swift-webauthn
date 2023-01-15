enum COSECurve: UInt64 {
    /// EC2, NIST P-256 also known as secp256r1
    case p256 = 1
    /// EC2, NIST P-384 also known as secp384r1
    case p384 = 2
    /// EC2, NIST P-521 also known as secp521r1
    case p521 = 3
    /// OKP, Ed25519 for use w/ EdDSA only
    case ed25519 = 6
}