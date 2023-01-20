import Foundation

/// On successful authentication, this structure contains a summary of the authentication flow
public struct VerifiedAuthentication {
    public enum CredentialDeviceType: String, Codable {
        case singleDevice = "single_device"
        case multiDevice = "multi_device"
    }

    let credentialID: URLEncodedBase64
    let newSignCount: UInt32
    let credentialDeviceType: CredentialDeviceType
    let credentialBackedUp: Bool
}
