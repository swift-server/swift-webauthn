public enum WebAuthnError: Error {
    case authDataTooShort
    case extensionDataMissing
    case leftOverBytes
    case attestedCredentialFlagNotSet
    case attestedCredentialDataMissing
    case badRequestData
    case validationError
}
