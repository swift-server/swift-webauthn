import XCTest
@testable import WebAuthn

final class AuthenticatorDataTests: XCTestCase {
    // Information about authenticator data: https://w3c.github.io/webauthn/#authenticator-data

    // Authenticator data
    let rpIdHash = [UInt8](repeating: 0, count: 32)
    let signCount = [UInt8](repeating: 0, count: 4)

    // Attested credential data
    let aaguid = [UInt8](repeating: 0, count: 16)
    let publicKeyBytes: [UInt8] = [1, 2, 3, 4, 5, 6]

    func testInitFromBytesFailsIfAuthDataIsTooShort() throws {
        let tooManyBytes = [UInt8](repeating: 1, count: 36)
        XCTAssertThrowsError(try AuthenticatorData(bytes: Data(tooManyBytes))) { error in
            XCTAssertEqual(error as? WebAuthnError, .authDataTooShort)
        }
    }

    func testInitFromBytesFailsIfAttestedCredentialDataFlagIsSetButDataIsActuallyNotThere() throws {
        let flagsByte: [UInt8] = [0b01000000] // "attested credential data included"

        let bytes = rpIdHash + flagsByte + signCount

        XCTAssertThrowsError(try AuthenticatorData(bytes: Data(bytes))) { error in
            XCTAssertEqual(error as? WebAuthnError, .attestedCredentialDataMissing)
        }
    }

    func testInitFromBytesFailsIfAttestedCredentialDataFlagIsNotSetButThereActuallyIsData() throws {
        let flagsByte: [UInt8] = [0b00000000] // "attested credential data not included"
        let fakeAttestedCredentialData: [UInt8] = [UInt8](repeating: 0, count: 4)

        let bytes = rpIdHash + flagsByte + signCount + fakeAttestedCredentialData

        XCTAssertThrowsError(try AuthenticatorData(bytes: Data(bytes))) { error in
            XCTAssertEqual(error as? WebAuthnError, .attestedCredentialFlagNotSet)
        }
    }

    func testInitFromBytesFailsIfExtensionDataFlagIsSetButDataIsNotIncluded() throws {
        let flagsByte: [UInt8] = [0b10000000] // "extension data included"

        let bytes = rpIdHash + flagsByte + signCount

        XCTAssertThrowsError(try AuthenticatorData(bytes: Data(bytes))) { error in
            XCTAssertEqual(error as? WebAuthnError, .extensionDataMissing)
        }
    }

    func testInitFromBytesFailsIfCredentialIdIsTooShort() throws {
        let flagsByte: [UInt8] = [0b01000000] // "attested credential data included"

        let credentialLength: [UInt8] = [0, 0b00000010] // here we say credentialId has length 2
        let credentialID: [UInt8] = [13] // but we only provide a credentialId of length 1

        let attestedCredentialData = aaguid + credentialLength + credentialID
        let bytes = rpIdHash + flagsByte + signCount + attestedCredentialData

        XCTAssertThrowsError(try AuthenticatorData(bytes: Data(bytes))) { error in
            XCTAssertEqual(error as? WebAuthnError, .credentialIDTooShort)
        }
    }

    func testInitFromBytesSucceeds() throws {
        let flagsByte: [UInt8] = [0b01000000] // "attested credential data included"

        let credentialLength: [UInt8] = [0, 0b00000010] // here we say credentialId has length 2
        let credentialID: [UInt8] = [13, 12] // but we only provide a credentialId of length 1

        let attestedCredentialData = aaguid + credentialLength + credentialID
        let bytes = rpIdHash + flagsByte + signCount + attestedCredentialData + publicKeyBytes

        let authenticatorData = try AuthenticatorData(bytes: Data(bytes))

        XCTAssertEqual(authenticatorData.relyingPartyIDHash, rpIdHash)
        XCTAssertEqual(
            authenticatorData.flags,
            .init(
                userPresent: false,
                userVerified: false,
                isBackupEligible: false,
                isCurrentlyBackedUp: false,
                attestedCredentialData: true,
                extensionDataIncluded: false
            )
        )
        XCTAssertEqual(authenticatorData.counter, Data(signCount).toInteger(endian: .big))
        XCTAssertEqual(authenticatorData.extData, nil)
        XCTAssertEqual(authenticatorData.attestedData?.aaguid, aaguid)
        XCTAssertEqual(authenticatorData.attestedData?.credentialID, credentialID)
        XCTAssertEqual(authenticatorData.attestedData?.publicKey, publicKeyBytes)
    }
}
