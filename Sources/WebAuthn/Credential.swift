import Foundation
import Crypto

public struct Credential {
    /// base64 encoded String of the credential ID bytes
    public let credentialID: String
    
    /// The public key for this certificate
    public let publicKey: P256.Signing.PublicKey
}
