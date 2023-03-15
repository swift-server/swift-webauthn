import Foundation

/// On successful authentication, this structure contains a summary of the authentication flow
public struct VerifiedAuthentication {
    public enum CredentialDeviceType: String, Codable {
        case singleDevice = "single_device"
        case multiDevice = "multi_device"
    }

    public let credentialID: URLEncodedBase64
    public let newSignCount: UInt32
    public let credentialDeviceType: CredentialDeviceType
    public let credentialBackedUp: Bool
}
