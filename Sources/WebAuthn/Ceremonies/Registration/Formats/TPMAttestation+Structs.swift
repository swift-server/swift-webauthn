// import Foundation
// extension TPMAttestation {
//     enum CertInfoError: Error {
//         case magicInvalid
//         case typeInvalid
//         case dataTooShort
//         case tpmImplementationIsWIP
//     }

//     struct AttestationInformation {
//         let name: Data
//         let qualifiedName: Data
//     }

//     struct CertInfo {
//         let magic: Data
//         let type: Data
//         let qualifiedSigner: Data
//         let extraData: Data
//         let clockInfo: Data
//         let firmwareVersion: Data
//         let attested: AttestationInformation

//         init?(fromBytes data: Data) {
//             var pointer = 0

//             guard let magic = data[safe: pointer..<(pointer + 4)] else { return nil }
//             self.magic = magic
//             pointer += 4

//             guard let type = data[safe: pointer..<(pointer + 2)] else { return nil }
//             self.type = type
//             pointer += 2

//             guard let qualifiedSignerLengthData = data[safe: pointer..<(pointer + 2)] else { return nil }
//             pointer += 2
//             let qualifiedSignerLength: Int = qualifiedSignerLengthData.toInteger(endian: .big)
//             guard let qualifiedSigner = data[safe: pointer..<(pointer + qualifiedSignerLength)] else { return nil }
//             self.qualifiedSigner = qualifiedSigner
//             pointer += qualifiedSignerLength

//             guard let extraDataLengthData = data[safe: pointer..<(pointer + 2)] else { return nil }
//             pointer += 2
//             let extraDataLength: Int = extraDataLengthData.toInteger(endian: .big)
//             guard let extraData = data[safe: pointer..<(pointer + extraDataLength)] else { return nil }
//             self.extraData = extraData
//             pointer += extraDataLength

//             guard let clockInfo = data[safe: pointer..<(pointer + 17)] else { return nil }
//             self.clockInfo = clockInfo
//             pointer += 17

//             guard let firmwareVersion = data[safe: pointer..<(pointer + 8)] else { return nil }
//             self.firmwareVersion = firmwareVersion
//             pointer += 8

//             guard let attestedNameLengthData = data[safe: pointer..<(pointer + 2)] else { return nil }
//             pointer += 2
//             let attestedNameLength: Int = attestedNameLengthData.toInteger(endian: .big)
//             guard let attestedName = data[safe: pointer..<(pointer + attestedNameLength)] else { return nil }
//             pointer += attestedNameLength

//             guard let qualifiedNameLengthData = data[safe: pointer..<(pointer + 2)] else { return nil }
//             pointer += 2
//             let qualifiedNameLength: Int = qualifiedNameLengthData.toInteger(endian: .big)
//             guard let qualifiedName = data[safe: pointer..<(pointer + qualifiedNameLength)] else { return nil }
//             pointer += qualifiedNameLength

//             attested = AttestationInformation(name: attestedName, qualifiedName: qualifiedName)
//         }

//         func verify() throws {
//             let tpmGeneratedValue = 0xFF544347
//             guard magic.toInteger(endian: .big) == tpmGeneratedValue else {
//                 throw CertInfoError.magicInvalid
//             }

//             let tpmStAttestCertify = 0x8017
//             guard type.toInteger(endian: .big) == tpmStAttestCertify else {
//                 throw CertInfoError.typeInvalid
//             }

//             throw CertInfoError.tpmImplementationIsWIP
//         }
//     }

//     enum PubAreaParameters {
//         case rsa(PubAreaParametersRSA)
//         case ecc (PubAreaParametersECC)
//     }

//     struct PubArea {
//         let type: Data
//         let nameAlg: Data
//         let objectAttributes: Data
//         let authPolicy: Data
//         let parameters: PubAreaParameters
//         let unique: PubAreaUnique

//         let mappedType: TPMAlg

//         init?(from data: Data) {
//             var pointer = 0

//             guard let type = data.safeSlice(length: 2, using: &pointer),
//                 let mappedType = TPMAlg(from: type),
//                 let nameAlg = data.safeSlice(length: 2, using: &pointer),
//                 let objectAttributes = data.safeSlice(length: 4, using: &pointer),
//                 let authPolicyLength: Int = data.safeSlice(length: 2, using: &pointer)?.toInteger(endian: .big),
//                 let authPolicy = data.safeSlice(length: authPolicyLength, using: &pointer) else {
//                 return nil
//             }

//             self.type = type
//             self.nameAlg = nameAlg
//             self.objectAttributes = objectAttributes
//             self.authPolicy = authPolicy

//             self.mappedType = mappedType

//             switch mappedType {
//             case .rsa:
//                 guard let rsa = data.safeSlice(length: 10, using: &pointer),
//                     let parameters = PubAreaParametersRSA(from: rsa) else { return nil }
//                 self.parameters = .rsa(parameters)
//             case .ecc:
//                 guard let ecc = data.safeSlice(length: 8, using: &pointer),
//                     let parameters = PubAreaParametersECC(from: ecc) else { return nil }
//                 self.parameters = .ecc(parameters)
//             default:
//                 return nil
//             }

//             guard data.count >= pointer,
//                 let unique = PubAreaUnique(from: data[pointer...], algorithm: mappedType) else {
//                 return nil
//             }

//             self.unique = unique
//         }
//     }
// }

// extension TPMAttestation {
//     enum TPMAlg: String {
//         case error = "TPM_ALG_ERROR"
//         case rsa = "TPM_ALG_RSA"
//         case sha1 = "TPM_ALG_SHA1"
//         case hmac = "TPM_ALG_HMAC"
//         case aes = "TPM_ALG_AES"
//         case mgf1 = "TPM_ALG_MGF1"
//         case keyedhash = "TPM_ALG_KEYEDHASH"
//         case xor = "TPM_ALG_XOR"
//         case sha256 = "TPM_ALG_SHA256"
//         case sha384 = "TPM_ALG_SHA384"
//         case sha512 = "TPM_ALG_SHA512"
//         case null = "TPM_ALG_NULL"
//         case sm3256 = "TPM_ALG_SM3_256"
//         case sm4 = "TPM_ALG_SM4"
//         case rsassa = "TPM_ALG_RSASSA"
//         case rsaes = "TPM_ALG_RSAES"
//         case rsapss = "TPM_ALG_RSAPSS"
//         case oaep = "TPM_ALG_OAEP"
//         case ecdsa = "TPM_ALG_ECDSA"
//         case ecdh = "TPM_ALG_ECDH"
//         case ecdaa = "TPM_ALG_ECDAA"
//         case sm2 = "TPM_ALG_SM2"
//         case ecschnorr = "TPM_ALG_ECSCHNORR"
//         case ecmqv = "TPM_ALG_ECMQV"
//         case kdf1Sp80056a = "TPM_ALG_KDF1_SP800_56A"
//         case kdf2 = "TPM_ALG_KDF2"
//         case kdf1Sp800108 = "TPM_ALG_KDF1_SP800_108"
//         case ecc = "TPM_ALG_ECC"
//         case symcipher = "TPM_ALG_SYMCIPHER"
//         case camellia = "TPM_ALG_CAMELLIA"
//         case ctr = "TPM_ALG_CTR"
//         case ofb = "TPM_ALG_OFB"
//         case cbc = "TPM_ALG_CBC"
//         case cfb = "TPM_ALG_CFB"
//         case ecb = "TPM_ALG_ECB"

//         // swiftlint:disable:next cyclomatic_complexity function_body_length
//         init?(from data: Data) {
//             let bytes = [UInt8](data)
//             switch bytes {
//             case [0x00, 0x00]:
//                 self = .error
//             case [0x00, 0x01]:
//                 self = .rsa
//             case [0x00, 0x04]:
//                 self = .sha1
//             case [0x00, 0x05]:
//                 self = .hmac
//             case [0x00, 0x06]:
//                 self = .aes
//             case [0x00, 0x07]:
//                 self = .mgf1
//             case [0x00, 0x08]:
//                 self = .keyedhash
//             case [0x00, 0x0a]:
//                 self = .xor
//             case [0x00, 0x0b]:
//                 self = .sha256
//             case [0x00, 0x0c]:
//                 self = .sha384
//             case [0x00, 0x0d]:
//                 self = .sha512
//             case [0x00, 0x10]:
//                 self = .null
//             case [0x00, 0x12]:
//                 self = .sm3256
//             case [0x00, 0x13]:
//                 self = .sm4
//             case [0x00, 0x14]:
//                 self = .rsassa
//             case [0x00, 0x15]:
//                 self = .rsaes
//             case [0x00, 0x16]:
//                 self = .rsapss
//             case [0x00, 0x17]:
//                 self = .oaep
//             case [0x00, 0x18]:
//                 self = .ecdsa
//             case [0x00, 0x19]:
//                 self = .ecdh
//             case [0x00, 0x1a]:
//                 self = .ecdaa
//             case [0x00, 0x1b]:
//                 self = .sm2
//             case [0x00, 0x1c]:
//                 self = .ecschnorr
//             case [0x00, 0x1d]:
//                 self = .ecmqv
//             case [0x00, 0x20]:
//                 self = .kdf1Sp80056a
//             case [0x00, 0x21]:
//                 self = .kdf2
//             case [0x00, 0x22]:
//                 self = .kdf1Sp800108
//             case [0x00, 0x23]:
//                 self = .ecc
//             case [0x00, 0x25]:
//                 self = .symcipher
//             case [0x00, 0x26]:
//                 self = .camellia
//             case [0x00, 0x40]:
//                 self = .ctr
//             case [0x00, 0x41]:
//                 self = .ofb
//             case [0x00, 0x42]:
//                 self = .cbc
//             case [0x00, 0x43]:
//                 self = .cfb
//             case [0x00, 0x44]:
//                 self = .ecb
//             default:
//                 return nil
//             }
//         }
//     }
// }

// extension TPMAttestation {
//     enum ECCCurve: String {
//         case none = "NONE"
//         case nistP192 = "NIST_P192"
//         case nistP224 = "NIST_P224"
//         case nistP256 = "NIST_P256"
//         case nistP384 = "NIST_P384"
//         case nistP521 = "NIST_P521"
//         case bnP256 = "BN_P256"
//         case bnP638 = "BN_P638"
//         case sm2P256 = "SM2_P256"

//         init?(from data: Data) {
//             let bytes = [UInt8](data)
//             switch bytes {
//             case [0x00, 0x00]:
//                 self = .none
//             case [0x00, 0x01]:
//                 self = .nistP192
//             case [0x00, 0x02]:
//                 self = .nistP224
//             case [0x00, 0x03]:
//                 self = .nistP256
//             case [0x00, 0x04]:
//                 self = .nistP384
//             case [0x00, 0x05]:
//                 self = .nistP521
//             case [0x00, 0x10]:
//                 self = .bnP256
//             case [0x00, 0x11]:
//                 self = .bnP638
//             case [0x00, 0x20]:
//                 self = .sm2P256
//             default:
//                 return nil
//             }
//         }
//     }
// }

// extension TPMAttestation {
//     struct PubAreaParametersRSA {
//         let symmetric: TPMAlg
//         let scheme: TPMAlg
//         let key: Data
//         let exponent: Data

//         init?(from data: Data) {
//             guard let symmetricData = data[safe: 0..<2],
//                 let symmetric = TPMAlg(from: symmetricData),
//                 let schemeData = data[safe: 2..<4],
//                 let scheme = TPMAlg(from: schemeData),
//                 let key = data[safe: 4..<6],
//                 let exponent = data[safe: 6..<10] else {
//                     return nil
//                 }

//             self.symmetric = symmetric
//             self.scheme = scheme
//             self.key = key
//             self.exponent = exponent
//         }
//     }
// }

// extension TPMAttestation {
//     struct PubAreaParametersECC {
//         let symmetric: TPMAlg
//         let scheme: TPMAlg
//         let curveID: ECCCurve
//         let kdf: TPMAlg

//         init?(from data: Data) {
//             guard let symmetricData = data[safe: 0..<2],
//                 let symmetric = TPMAlg(from: symmetricData),
//                 let schemeData = data[safe: 2..<4],
//                 let scheme = TPMAlg(from: schemeData),
//                 let curveIDData = data[safe: 4..<6],
//                 let curveID = ECCCurve(from: curveIDData),
//                 let kdfData = data[safe: 6..<8],
//                 let kdf = TPMAlg(from: kdfData) else {
//                     return nil
//                 }

//             self.symmetric = symmetric
//             self.scheme = scheme
//             self.curveID = curveID
//             self.kdf = kdf
//         }
//     }
// }

// extension TPMAttestation {
//     struct PubAreaUnique {
//         let data: Data

//         init?(from data: Data, algorithm: TPMAlg) {
//             switch algorithm {
//             case .rsa:
//                 guard let uniqueLength: Int = data[safe: 0..<2]?.toInteger(endian: .big),
//                     let rsaUnique = data[safe: 2..<(2 + uniqueLength)] else {
//                         return nil
//                     }
//                 self.data = rsaUnique
//             case .ecc:
//                 var pointer = 0
//                 guard let uniqueXLength: Int = data.safeSlice(length: 2, using: &pointer)?.toInteger(endian: .big),
//                     let uniqueX = data.safeSlice(length: uniqueXLength, using: &pointer),
//                     let uniqueYLength: Int = data.safeSlice(length: 2, using: &pointer)?.toInteger(endian: .big),
//                     let uniqueY = data.safeSlice(length: uniqueYLength, using: &pointer) else {
//                         return nil
//                     }
//                 self.data = uniqueX + uniqueY
//             default:
//                 return nil
//             }
//         }
//     }
// }

// extension COSECurve {
//     init?(from eccCurve: TPMAttestation.ECCCurve) {
//         switch eccCurve {
//         case .nistP256, .bnP256, .sm2P256:
//             self = .p256
//         case .nistP384:
//             self = .p384
//         case .nistP521:
//             self = .p521
//         default:
//             return nil
//         }
//     }
// }