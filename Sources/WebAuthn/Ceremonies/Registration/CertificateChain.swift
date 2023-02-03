import Foundation
import CJWTKitBoringSSL
import Crypto

struct CertificateChain {
    enum CertificateChainError: Error {
        case emptyX5C
        case certificateValidationFailed
    }

    static func validate(x5c: [Data], pemRootCertificateBytes: [Data]? = nil) throws {
        guard let pemRootCertificateBytes, !pemRootCertificateBytes.isEmpty else {
            // We have no root certs to chain back to, so just pass on validation
            return
        }

        guard x5c.count >= 1 else {
            throw CertificateChainError.emptyX5C
        }

        let rootCertificate = try OpenSSLKey.load(pem: pemRootCertificateBytes[0]) { bio in
            CJWTKitBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
        }
        defer { CJWTKitBoringSSL_X509_free(rootCertificate) }

        let leafCertificateBytes = x5c[0]
        let leafCertificate = try OpenSSLKey.load(pem: leafCertificateBytes) { bio in
            CJWTKitBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
        }
        defer { CJWTKitBoringSSL_X509_free(leafCertificate) }

        let rootPublicKey = CJWTKitBoringSSL_X509_get_pubkey(rootCertificate)
        defer { CJWTKitBoringSSL_EVP_PKEY_free(rootPublicKey) }

        // problem: we only verify root and leaf certificate here. Intermediates are missing!

        guard CJWTKitBoringSSL_X509_verify(leafCertificate, rootPublicKey) == 1 else {
            throw CertificateChainError.certificateValidationFailed
        }
    }
}

extension CertificateChain {
    struct OpenSSLKey {
        private enum OpenSSLError: Error {
            case digestInitializationFailure
            case digestUpdateFailure
            case digestFinalizationFailure
            case bioPutsFailure
            case bioConversionFailure
        }

        static func load<Data, T>(
            pem data: Data,
            _ closure: (UnsafeMutablePointer<BIO>) -> (T?)
        ) throws -> T where Data: DataProtocol {
            let bytes = [UInt8](data)
            let bio = CJWTKitBoringSSL_BIO_new_mem_buf(bytes, numericCast(bytes.count))
            defer { CJWTKitBoringSSL_BIO_free(bio) }

            guard let bioPtr = bio, let closure = closure(bioPtr) else {
                throw OpenSSLError.bioConversionFailure
            }
            return closure
        }
    }
}