/**
 * Windows CNG N-API native addon for OpenCred.
 *
 * Interfaces with Windows CNG (Cryptography API: Next Generation) and
 * CryptoAPI to enumerate certificates and sign data using Windows-managed
 * private keys. The private key NEVER leaves the Windows certificate store.
 *
 * SECURITY INVARIANTS:
 *  - No function exports or logs private key material.
 *  - Only certificate metadata and public keys are returned to JS.
 *  - Signing is delegated entirely to NCryptSignHash().
 *  - EC signatures from CNG are already in raw r||s format.
 *  - All handles (NCRYPT_KEY_HANDLE, PCCERT_CONTEXT) are properly released.
 */

#ifdef _WIN32

#include <napi.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <cctype>
#include <vector>
#include <string>

// CERT_FIND_SHA_256_HASH may not be defined in older Windows SDK headers
#ifndef CERT_FIND_SHA_256_HASH
#define CERT_FIND_SHA_256_HASH (CERT_COMPARE_SHA_256_HASH << CERT_COMPARE_SHIFT)
#endif
#ifndef CERT_COMPARE_SHA_256_HASH
#define CERT_COMPARE_SHA_256_HASH 19
#endif
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

// ---------------------------------------------------------------------------
// Helper: Wide string → UTF-8 string
// ---------------------------------------------------------------------------
static std::string WideToUtf8(const wchar_t *wide) {
    if (!wide) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, &result[0], len, nullptr, nullptr);
    return result;
}

// ---------------------------------------------------------------------------
// Helper: Compute SHA-256 thumbprint of DER data (hex-encoded)
// ---------------------------------------------------------------------------
static std::string ComputeThumbprint(const BYTE *data, DWORD dataLen) {
    BYTE hash[32]; // SHA-256
    DWORD hashLen = sizeof(hash);
    if (!CryptHashCertificate(0, CALG_SHA_256, 0, data, dataLen, hash, &hashLen)) {
        return "";
    }

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (DWORD i = 0; i < hashLen; i++) {
        hex << std::setw(2) << (int)hash[i];
    }
    return hex.str();
}

// ---------------------------------------------------------------------------
// Helper: FILETIME → ISO 8601 string
// ---------------------------------------------------------------------------
static std::string FileTimeToISO8601(const FILETIME &ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Helper: Extract CN from certificate name blob
// ---------------------------------------------------------------------------
static std::string ExtractCN(PCERT_NAME_BLOB nameBlob) {
    DWORD len = CertNameToStrW(X509_ASN_ENCODING, nameBlob,
        CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, nullptr, 0);
    if (len <= 1) return "";

    std::vector<wchar_t> buf(len);
    CertNameToStrW(X509_ASN_ENCODING, nameBlob,
        CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, buf.data(), len);
    return WideToUtf8(buf.data());
}

// ---------------------------------------------------------------------------
// Helper: Get key algorithm string from certificate context
// ---------------------------------------------------------------------------
static std::string GetKeyAlgorithmString(PCCERT_CONTEXT certCtx) {
    PCERT_PUBLIC_KEY_INFO pubKeyInfo = &certCtx->pCertInfo->SubjectPublicKeyInfo;
    std::string oid = pubKeyInfo->Algorithm.pszObjId;

    if (oid == szOID_ECC_PUBLIC_KEY) {
        // EC key — determine curve from parameters
        if (pubKeyInfo->Algorithm.Parameters.cbData > 0) {
            std::string paramOid;
            DWORD decodedSize = 0;
            if (CryptDecodeObject(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER,
                    pubKeyInfo->Algorithm.Parameters.pbData,
                    pubKeyInfo->Algorithm.Parameters.cbData,
                    0, nullptr, &decodedSize)) {
                std::vector<BYTE> decoded(decodedSize);
                if (CryptDecodeObject(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER,
                        pubKeyInfo->Algorithm.Parameters.pbData,
                        pubKeyInfo->Algorithm.Parameters.cbData,
                        0, decoded.data(), &decodedSize)) {
                    paramOid = (char *)decoded.data();
                }
            }

            if (paramOid == szOID_ECC_CURVE_P384) return "P-384";
        }
        return "P-256";
    } else if (oid == szOID_RSA_RSA) {
        DWORD keySize = CertGetPublicKeyLength(X509_ASN_ENCODING, pubKeyInfo);
        return "RSA-" + std::to_string(keySize);
    }

    return "";
}

// ---------------------------------------------------------------------------
// Helper: Get serial number as hex string
// ---------------------------------------------------------------------------
static std::string GetSerialNumberHex(PCRYPT_INTEGER_BLOB serial) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    // Serial number is stored in little-endian in Windows, reverse for display
    for (int i = (int)serial->cbData - 1; i >= 0; i--) {
        hex << std::setw(2) << (int)serial->pbData[i];
    }
    return hex.str();
}

// ---------------------------------------------------------------------------
// Helper: Check if key is exportable via CNG
// ---------------------------------------------------------------------------
static bool IsKeyExportable(PCCERT_CONTEXT certCtx) {
    NCRYPT_KEY_HANDLE keyHandle = 0;
    DWORD keySpec = 0;
    BOOL callerFree = FALSE;

    if (!CryptAcquireCertificatePrivateKey(certCtx,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
            nullptr, &keyHandle, &keySpec, &callerFree)) {
        return false;
    }

    DWORD exportPolicy = 0;
    DWORD resultLen = 0;
    SECURITY_STATUS st = NCryptGetProperty(keyHandle,
        NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&exportPolicy,
        sizeof(exportPolicy), &resultLen, 0);

    if (callerFree) NCryptFreeObject(keyHandle);

    if (st != ERROR_SUCCESS) return false;
    return (exportPolicy & NCRYPT_ALLOW_EXPORT_FLAG) != 0;
}

// ---------------------------------------------------------------------------
// Helper: Find certificate by thumbprint
//
// SECURITY: Validates that every character in the thumbprint is a hex digit
// and checks sscanf return value to prevent using uninitialised stack memory
// in the certificate store search blob.
// ---------------------------------------------------------------------------
static PCCERT_CONTEXT FindCertByThumbprint(HCERTSTORE store, const std::string &thumbprint) {
    // SHA-256 thumbprint = 32 bytes = 64 hex characters
    if (thumbprint.size() != 64) return nullptr;

    // Validate all characters are hex digits before parsing
    for (char c : thumbprint) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return nullptr;
        }
    }

    BYTE hashBytes[32];
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        if (sscanf(thumbprint.c_str() + i * 2, "%02x", &byte) != 1) {
            return nullptr;
        }
        hashBytes[i] = (BYTE)byte;
    }

    CRYPT_HASH_BLOB hashBlob;
    hashBlob.cbData = sizeof(hashBytes);
    hashBlob.pbData = hashBytes;

    return CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0, CERT_FIND_SHA_256_HASH, &hashBlob, nullptr);
}

// ---------------------------------------------------------------------------
// Helper: Compress EC point
// ---------------------------------------------------------------------------
static std::vector<BYTE> CompressEcPoint(const BYTE *uncompressed, DWORD len) {
    if (len < 3 || uncompressed[0] != 0x04) {
        return std::vector<BYTE>(uncompressed, uncompressed + len);
    }
    DWORD coordLen = (len - 1) / 2;
    BYTE prefix = (uncompressed[1 + coordLen + coordLen - 1] & 1) ? 0x03 : 0x02;
    std::vector<BYTE> compressed(1 + coordLen);
    compressed[0] = prefix;
    memcpy(compressed.data() + 1, uncompressed + 1, coordLen);
    return compressed;
}

// ===========================================================================
// N-API: listSigningCertificates()
// ===========================================================================
static Napi::Value ListSigningCertificates(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"MY");

    Napi::Array result = Napi::Array::New(env);
    if (!store) return result;

    PCCERT_CONTEXT certCtx = nullptr;
    uint32_t idx = 0;

    while ((certCtx = CertEnumCertificatesInStore(store, certCtx)) != nullptr) {
        // Check if this certificate has a private key
        DWORD keySpec = 0;
        BOOL callerFree = FALSE;
        NCRYPT_KEY_HANDLE keyHandle = 0;

        if (!CryptAcquireCertificatePrivateKey(certCtx,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                nullptr, &keyHandle, &keySpec, &callerFree)) {
            continue; // No private key associated
        }
        if (callerFree) NCryptFreeObject(keyHandle);

        // Get algorithm — filter to EC and RSA only
        std::string keyAlgorithm = GetKeyAlgorithmString(certCtx);
        if (keyAlgorithm.empty()) continue;

        // Certificate metadata
        std::string subject = ExtractCN(&certCtx->pCertInfo->Subject);
        std::string issuer = ExtractCN(&certCtx->pCertInfo->Issuer);
        std::string serialNumber = GetSerialNumberHex(&certCtx->pCertInfo->SerialNumber);
        std::string validFrom = FileTimeToISO8601(certCtx->pCertInfo->NotBefore);
        std::string validUntil = FileTimeToISO8601(certCtx->pCertInfo->NotAfter);

        std::string thumbprint = ComputeThumbprint(
            certCtx->pbCertEncoded, certCtx->cbCertEncoded);

        bool isExportable = IsKeyExportable(certCtx);

        Napi::Object certObj = Napi::Object::New(env);
        certObj.Set("id", thumbprint);
        certObj.Set("subject", subject);
        certObj.Set("issuer", issuer);
        certObj.Set("serialNumber", serialNumber);
        certObj.Set("validFrom", validFrom);
        certObj.Set("validUntil", validUntil);
        certObj.Set("keyAlgorithm", keyAlgorithm);
        certObj.Set("isExportable", isExportable);
        certObj.Set("thumbprint", thumbprint);

        result.Set(idx++, certObj);
    }

    CertCloseStore(store, 0);
    return result;
}

// ===========================================================================
// N-API: signWithCertificate(id, data)
// ===========================================================================
static Napi::Value SignWithCertificate(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsBuffer()) {
        Napi::Error::New(env, "Expected (string certificateId, Buffer data)").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string thumbprint = info[0].As<Napi::String>().Utf8Value();
    Napi::Buffer<uint8_t> dataBuffer = info[1].As<Napi::Buffer<uint8_t>>();

    if (thumbprint.empty()) {
        Napi::Error::New(env, "Certificate ID must not be empty").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"MY");

    if (!store) {
        Napi::Error::New(env, "Failed to open Windows certificate store").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    PCCERT_CONTEXT certCtx = FindCertByThumbprint(store, thumbprint);
    if (!certCtx) {
        CertCloseStore(store, 0);
        Napi::Error::New(env, "Certificate not found in store").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // Acquire the CNG private key
    NCRYPT_KEY_HANDLE keyHandle = 0;
    DWORD keySpec = 0;
    BOOL callerFree = FALSE;

    if (!CryptAcquireCertificatePrivateKey(certCtx,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, nullptr,
            &keyHandle, &keySpec, &callerFree)) {
        CertFreeCertificateContext(certCtx);
        CertCloseStore(store, 0);
        Napi::Error::New(env, "Failed to acquire private key").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // Determine padding based on key type
    std::string algo = GetKeyAlgorithmString(certCtx);
    bool isEC = algo.find("P-") == 0;

    DWORD sigLen = 0;
    SECURITY_STATUS st;

    if (isEC) {
        // ECDSA — no padding info needed
        st = NCryptSignHash(keyHandle, nullptr,
            (PBYTE)dataBuffer.Data(), (DWORD)dataBuffer.Length(),
            nullptr, 0, &sigLen, 0);
    } else {
        // RSA-PSS
        BCRYPT_PSS_PADDING_INFO pssInfo;
        pssInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        pssInfo.cbSalt = 32; // SHA-256 digest length

        st = NCryptSignHash(keyHandle, &pssInfo,
            (PBYTE)dataBuffer.Data(), (DWORD)dataBuffer.Length(),
            nullptr, 0, &sigLen, BCRYPT_PAD_PSS);
    }

    if (st != ERROR_SUCCESS || sigLen == 0) {
        if (callerFree) NCryptFreeObject(keyHandle);
        CertFreeCertificateContext(certCtx);
        CertCloseStore(store, 0);
        Napi::Error::New(env, "Signing operation failed").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::vector<BYTE> signature(sigLen);

    if (isEC) {
        st = NCryptSignHash(keyHandle, nullptr,
            (PBYTE)dataBuffer.Data(), (DWORD)dataBuffer.Length(),
            signature.data(), sigLen, &sigLen, 0);
    } else {
        BCRYPT_PSS_PADDING_INFO pssInfo;
        pssInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        pssInfo.cbSalt = 32;

        st = NCryptSignHash(keyHandle, &pssInfo,
            (PBYTE)dataBuffer.Data(), (DWORD)dataBuffer.Length(),
            signature.data(), sigLen, &sigLen, BCRYPT_PAD_PSS);
    }

    if (callerFree) NCryptFreeObject(keyHandle);
    CertFreeCertificateContext(certCtx);
    CertCloseStore(store, 0);

    if (st != ERROR_SUCCESS) {
        // SECURITY: Do not include error codes that might leak key info
        Napi::Error::New(env, "Signing operation failed").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // CNG ECDSA already returns raw r||s, no DER conversion needed
    return Napi::Buffer<uint8_t>::Copy(env, signature.data(), sigLen);
}

// ===========================================================================
// N-API: getPublicKey(id)
// ===========================================================================
static Napi::Value GetPublicKey(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::Error::New(env, "Expected (string certificateId)").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string thumbprint = info[0].As<Napi::String>().Utf8Value();

    if (thumbprint.empty()) {
        Napi::Error::New(env, "Certificate ID must not be empty").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"MY");

    if (!store) {
        Napi::Error::New(env, "Failed to open Windows certificate store").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    PCCERT_CONTEXT certCtx = FindCertByThumbprint(store, thumbprint);
    if (!certCtx) {
        CertCloseStore(store, 0);
        Napi::Error::New(env, "Certificate not found in store").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    PCERT_PUBLIC_KEY_INFO pubKeyInfo = &certCtx->pCertInfo->SubjectPublicKeyInfo;
    std::string algo = GetKeyAlgorithmString(certCtx);
    bool isEC = algo.find("P-") == 0;

    Napi::Buffer<uint8_t> resultBuffer;

    if (isEC) {
        // EC: extract the public key point and compress it
        const BYTE *keyData = pubKeyInfo->PublicKey.pbData;
        DWORD keyLen = pubKeyInfo->PublicKey.cbData;

        // The public key data contains the uncompressed point
        // First byte might be 0x00 (unused bits), skip if present in BIT STRING
        if (keyLen > 0 && keyData[0] == 0x04) {
            // Already uncompressed point format
            std::vector<BYTE> compressed = CompressEcPoint(keyData, keyLen);
            resultBuffer = Napi::Buffer<uint8_t>::Copy(env, compressed.data(), (size_t)compressed.size());
        } else {
            resultBuffer = Napi::Buffer<uint8_t>::Copy(env, keyData, keyLen);
        }
    } else {
        // RSA: encode as SPKI DER
        DWORD encodedLen = 0;
        CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
            pubKeyInfo, nullptr, &encodedLen);

        if (encodedLen > 0) {
            std::vector<BYTE> encoded(encodedLen);
            CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                pubKeyInfo, encoded.data(), &encodedLen);
            resultBuffer = Napi::Buffer<uint8_t>::Copy(env, encoded.data(), encodedLen);
        } else {
            CertFreeCertificateContext(certCtx);
            CertCloseStore(store, 0);
            Napi::Error::New(env, "Failed to encode public key").ThrowAsJavaScriptException();
            return env.Undefined();
        }
    }

    CertFreeCertificateContext(certCtx);
    CertCloseStore(store, 0);
    return resultBuffer;
}

// ===========================================================================
// N-API: getCertificateChain(id)
// ===========================================================================
static Napi::Value GetCertificateChain(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::Error::New(env, "Expected (string certificateId)").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string thumbprint = info[0].As<Napi::String>().Utf8Value();

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"MY");

    Napi::Array result = Napi::Array::New(env);
    if (!store) return result;

    PCCERT_CONTEXT certCtx = FindCertByThumbprint(store, thumbprint);
    if (!certCtx) {
        CertCloseStore(store, 0);
        return result;
    }

    // Build the certificate chain
    CERT_CHAIN_PARA chainPara;
    ZeroMemory(&chainPara, sizeof(chainPara));
    chainPara.cbSize = sizeof(chainPara);

    PCCERT_CHAIN_CONTEXT chainCtx = nullptr;
    if (!CertGetCertificateChain(nullptr, certCtx, nullptr, store,
            &chainPara, 0, nullptr, &chainCtx)) {
        CertFreeCertificateContext(certCtx);
        CertCloseStore(store, 0);
        return result;
    }

    // Walk the chain
    if (chainCtx->cChain > 0) {
        PCERT_SIMPLE_CHAIN simpleChain = chainCtx->rgpChain[0];
        uint32_t idx = 0;

        for (DWORD i = 0; i < simpleChain->cElement; i++) {
            PCCERT_CONTEXT chainCert = simpleChain->rgpElement[i]->pCertContext;

            // Base64 encode DER → PEM
            DWORD base64Len = 0;
            CryptBinaryToStringA(chainCert->pbCertEncoded, chainCert->cbCertEncoded,
                CRYPT_STRING_BASE64, nullptr, &base64Len);

            if (base64Len > 0) {
                std::vector<char> base64(base64Len);
                CryptBinaryToStringA(chainCert->pbCertEncoded, chainCert->cbCertEncoded,
                    CRYPT_STRING_BASE64, base64.data(), &base64Len);

                std::string pem = "-----BEGIN CERTIFICATE-----\n";
                pem += std::string(base64.data(), base64Len);
                pem += "-----END CERTIFICATE-----";

                result.Set(idx++, pem);
            }
        }
    }

    CertFreeCertificateChain(chainCtx);
    CertFreeCertificateContext(certCtx);
    CertCloseStore(store, 0);
    return result;
}

// ===========================================================================
// Module initialization
// ===========================================================================
static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("listSigningCertificates",
        Napi::Function::New(env, ListSigningCertificates));
    exports.Set("signWithCertificate",
        Napi::Function::New(env, SignWithCertificate));
    exports.Set("getPublicKey",
        Napi::Function::New(env, GetPublicKey));
    exports.Set("getCertificateChain",
        Napi::Function::New(env, GetCertificateChain));
    return exports;
}

NODE_API_MODULE(windows_cng, Init)

#endif // _WIN32
