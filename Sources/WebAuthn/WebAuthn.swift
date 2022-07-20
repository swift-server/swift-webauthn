import SwiftCBOR
import Crypto
import Logging
import Foundation

public enum WebAuthn {
    public static func validateAssertion(_ data: AssertionCredential, challengeProvided: String, publicKey: P256.Signing.PublicKey, logger: Logger) throws {
        guard let clientObjectData = Data(base64Encoded: data.response.clientDataJSON) else {
            throw WebAuthnError.badRequestData
        }
        let clientObject = try JSONDecoder().decode(ClientDataObject.self, from: clientObjectData)
        guard challengeProvided == clientObject.challenge else {
            throw WebAuthnError.validationError
        }
        let clientDataJSONHash = SHA256.hash(data: clientObjectData)
        
        var base64AssertionString = data.response.authenticatorData.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while base64AssertionString.count % 4 != 0 {
            base64AssertionString = base64AssertionString.appending("=")
        }
        guard let authenticatorData = Data(base64Encoded: base64AssertionString) else {
            throw WebAuthnError.badRequestData
        }
        let signedData = authenticatorData + clientDataJSONHash
        
        var base64SignatureString = data.response.signature.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while base64SignatureString.count % 4 != 0 {
            base64SignatureString = base64SignatureString.appending("=")
        }
        guard let signatureData = Data(base64Encoded: base64SignatureString) else {
            throw WebAuthnError.badRequestData
        }
        let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
        guard publicKey.isValidSignature(signature, for: signedData) else {
            throw WebAuthnError.validationError
        }
    }
    
    public static func parseRegisterCredentials(_ data: RegisterWebAuthnCredentialData, challengeProvided: String, origin: String, logger: Logger) throws -> Credential {
        guard let clientObjectData = Data(base64Encoded: data.response.clientDataJSON) else {
            throw WebAuthnError.badRequestData
        }
        let clientObject = try JSONDecoder().decode(ClientDataObject.self, from: clientObjectData)
        guard challengeProvided == clientObject.challenge else {
            throw WebAuthnError.validationError
        }
        guard clientObject.type == "webauthn.create" else {
            throw WebAuthnError.badRequestData
        }
        guard origin == clientObject.origin else {
            throw WebAuthnError.validationError
        }
        var base64AttestationString = data.response.attestationObject.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while base64AttestationString.count % 4 != 0 {
            base64AttestationString = base64AttestationString.appending("=")
        }
        guard let attestationData = Data(base64Encoded: base64AttestationString) else {
            throw WebAuthnError.badRequestData
        }
        guard let decodedAttestationObject = try CBOR.decode([UInt8](attestationData)) else {
            throw WebAuthnError.badRequestData
        }
        logger.debug("Got COBR decoded data: \(decodedAttestationObject)")
        
        // Ignore format/statement for now
        guard let authData = decodedAttestationObject["authData"], case let .byteString(authDataBytes) = authData else {
            throw WebAuthnError.badRequestData
        }
        guard let credentialsData = try parseAttestationObject(authDataBytes, logger: logger) else {
            throw WebAuthnError.badRequestData
        }
        guard let publicKeyObject = try CBOR.decode(credentialsData.publicKey) else {
            throw WebAuthnError.badRequestData
        }
        // This is now in COSE format
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        guard let keyTypeRaw = publicKeyObject[.unsignedInt(1)], case let .unsignedInt(keyType) = keyTypeRaw else {
            throw WebAuthnError.badRequestData
        }
        guard let algorithmRaw = publicKeyObject[.unsignedInt(3)], case let .negativeInt(algorithmNegative) = algorithmRaw else {
            throw WebAuthnError.badRequestData
        }
        // https://github.com/unrelentingtech/SwiftCBOR#swiftcbor
        // Negative integers are decoded as NegativeInt(UInt), where the actual number is -1 - i
        let algorithm: Int = -1 - Int(algorithmNegative)
        
        // Curve is key -1 - or -0 for SwiftCBOR
        // X Coordinate is key -2, or NegativeInt 1 for SwiftCBOR
        // Y Coordinate is key -3, or NegativeInt 2 for SwiftCBOR
        
        guard let curveRaw = publicKeyObject[.negativeInt(0)], case let .unsignedInt(curve) = curveRaw else {
            throw WebAuthnError.badRequestData
        }
        guard let xCoordRaw = publicKeyObject[.negativeInt(1)], case let .byteString(xCoordinateBytes) = xCoordRaw else {
            throw WebAuthnError.badRequestData
        }
        guard let yCoordRaw = publicKeyObject[.negativeInt(2)], case let .byteString(yCoordinateBytes) = yCoordRaw else {
            throw WebAuthnError.badRequestData
        }
        
        logger.debug("Key type was \(keyType)")
        logger.debug("Algorithm was \(algorithm)")
        logger.debug("Curve was \(curve)")
        
        let key = try P256.Signing.PublicKey(rawRepresentation: xCoordinateBytes + yCoordinateBytes)
        logger.debug("Key is \(key.pemRepresentation)")
        
        return Credential(credentialID: data.id, publicKey: key)
    }
    
    static func parseAttestedData(_ data: [UInt8], logger: Logger) throws -> AttestedCredentialData {
        // We've parsed the first 37 bytes so far, the next bytes now should be the attested credential data
        // See https://w3c.github.io/webauthn/#sctn-attested-credential-data
        let aaguidLength = 16
        let aaguid = data[37..<(37 + aaguidLength)] // To byte at index 52
        
        let idLengthBytes = data[53..<55] // Length is 2 bytes
        let idLengthData = Data(idLengthBytes)
        let idLength: UInt16 = idLengthData.toInteger(endian: .big)
        let credentialIDEndIndex = Int(idLength) + 55
        
        let credentialID = data[55..<credentialIDEndIndex]
        let publicKeyBytes = data[credentialIDEndIndex...]
        
        return AttestedCredentialData(aaguid: Array(aaguid), credentialID: Array(credentialID), publicKey: Array(publicKeyBytes))
    }
    
    static func parseAttestationObject(_ bytes: [UInt8], logger: Logger) throws -> AttestedCredentialData? {
        let minAuthDataLength = 37
        let minAttestedAuthLength = 55
        let maxCredentialIDLength = 1023
        // What to do when we don't have this
        var credentialsData: AttestedCredentialData? = nil
        
        guard bytes.count >= minAuthDataLength else {
            throw WebAuthnError.authDataTooShort
        }
        
        let rpIDHashData = bytes[..<32]
        let flags = AuthenticatorFlags(bytes[32])
        let counter: UInt32 = Data(bytes[33..<37]).toInteger(endian: .big)
        
        var remainingCount = bytes.count - minAuthDataLength
        
        if flags.attestedCredentialData {
            guard bytes.count > minAttestedAuthLength else {
                throw WebAuthnError.attestedCredentialDataMissing
            }
            let attestedCredentialData = try parseAttestedData(bytes, logger: logger)
            // 2 is the bytes storing the size of the credential ID
            let credentialDataLength = attestedCredentialData.aaguid.count + 2 + attestedCredentialData.credentialID.count + attestedCredentialData.publicKey.count
            remainingCount -= credentialDataLength
            credentialsData = attestedCredentialData
        } else {
            if !flags.extensionDataIncluded && bytes.count != minAuthDataLength {
                throw WebAuthnError.attestedCredentialFlagNotSet
            }
        }
        
        if flags.extensionDataIncluded {
            guard remainingCount != 0 else {
                throw WebAuthnError.extensionDataMissing
            }
            let extensionData = bytes[(bytes.count - remainingCount)...]
            remainingCount -= extensionData.count
        }
        
        guard remainingCount == 0 else {
            throw WebAuthnError.leftOverBytes
        }
        return credentialsData
    }
}
