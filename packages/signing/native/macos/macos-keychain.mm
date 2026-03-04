/**
 * macOS Keychain N-API native addon for OpenCred.
 *
 * Interfaces with Security.framework to enumerate certificates and sign
 * data using Keychain-managed private keys. The private key NEVER leaves
 * the Keychain — all signing is performed by SecKeyCreateSignature().
 *
 * SECURITY INVARIANTS:
 *  - No function exports or logs private key material.
 *  - Only certificate metadata and public keys are returned to JS.
 *  - Signing is delegated entirely to Security.framework.
 *  - EC signatures from macOS (DER/X9.62) are converted to raw r||s.
 *  - ARC manages all Objective-C object lifetimes.
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#include <napi.h>
#include <vector>
#include <string>

// ---------------------------------------------------------------------------
// RAII guard for CoreFoundation objects — prevents leaks on error paths
// ---------------------------------------------------------------------------
template<typename T>
struct CFGuard {
    T ref;
    CFGuard(T r) : ref(r) {}
    ~CFGuard() { if (ref) CFRelease(ref); }
    CFGuard(const CFGuard &) = delete;
    CFGuard &operator=(const CFGuard &) = delete;
    operator T() const { return ref; }
    T get() const { return ref; }
    T release() { T r = ref; ref = nullptr; return r; }
};

// ---------------------------------------------------------------------------
// Helper: CFStringRef → std::string
// ---------------------------------------------------------------------------
static std::string CFStringToStdString(CFStringRef cfStr) {
    if (!cfStr) return "";

    const char *cStr = CFStringGetCStringPtr(cfStr, kCFStringEncodingUTF8);
    if (cStr) return std::string(cStr);

    CFIndex length = CFStringGetLength(cfStr);
    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
    std::vector<char> buffer(maxSize);
    if (CFStringGetCString(cfStr, buffer.data(), maxSize, kCFStringEncodingUTF8)) {
        return std::string(buffer.data());
    }
    return "";
}

// ---------------------------------------------------------------------------
// Helper: CFDateRef → ISO 8601 string
// ---------------------------------------------------------------------------
static std::string CFDateToISO8601(CFDateRef date) {
    if (!date) return "";

    CFAbsoluteTime absTime = CFDateGetAbsoluteTime(date);
    // CFAbsoluteTime epoch is 2001-01-01 00:00:00 UTC
    // Convert to Unix epoch (1970-01-01) by adding the difference
    time_t unixTime = (time_t)(absTime + 978307200.0);
    struct tm tm;
    gmtime_r(&unixTime, &tm);

    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Helper: Compute SHA-256 thumbprint of DER data (hex-encoded)
// ---------------------------------------------------------------------------
static std::string ComputeThumbprint(CFDataRef derData) {
    if (!derData) return "";

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(CFDataGetBytePtr(derData), (CC_LONG)CFDataGetLength(derData), hash);

    char hex[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    }
    return std::string(hex, CC_SHA256_DIGEST_LENGTH * 2);
}

// ---------------------------------------------------------------------------
// Helper: Parse CN from a DER-encoded issuer/subject DN (best-effort)
//
// Walks the DER RDNSequence looking for OID 2.5.4.3 (commonName).
// Returns the UTF-8 value of the first CN found, or "".
// ---------------------------------------------------------------------------
static std::string ParseCNFromDERName(const uint8_t *data, size_t len) {
    // CN OID: 2.5.4.3 → DER 55 04 03
    static const uint8_t cnOid[] = { 0x55, 0x04, 0x03 };

    // Scan for the CN OID in the DER data
    for (size_t i = 0; i + sizeof(cnOid) + 2 < len; i++) {
        if (data[i] == 0x06 && data[i + 1] == 0x03 &&
            memcmp(data + i + 2, cnOid, sizeof(cnOid)) == 0) {
            // Found OID. The value follows: tag + length + value
            size_t valPos = i + 2 + sizeof(cnOid);
            if (valPos + 2 > len) break;

            uint8_t valTag = data[valPos];
            // Accept UTF8String (0x0C), PrintableString (0x13), IA5String (0x16)
            if (valTag != 0x0C && valTag != 0x13 && valTag != 0x16) continue;

            uint8_t valLen = data[valPos + 1];
            if (valLen > 127) continue; // Skip multi-byte lengths for simplicity
            if (valPos + 2 + valLen > len) continue;

            return std::string(reinterpret_cast<const char *>(data + valPos + 2), valLen);
        }
    }
    return "";
}

// ---------------------------------------------------------------------------
// Helper: Extract issuer CN from certificate (best-effort)
// ---------------------------------------------------------------------------
static std::string GetIssuerCN(SecCertificateRef cert) {
    CFDataRef issuerData = SecCertificateCopyNormalizedIssuerSequence(cert);
    if (!issuerData) return "Unknown Issuer";
    CFGuard<CFDataRef> issuerGuard(issuerData);

    const uint8_t *bytes = CFDataGetBytePtr(issuerData);
    size_t len = (size_t)CFDataGetLength(issuerData);

    std::string cn = ParseCNFromDERName(bytes, len);
    return cn.empty() ? "Unknown Issuer" : cn;
}

// ---------------------------------------------------------------------------
// Helper: Extract serial number from certificate (hex)
// ---------------------------------------------------------------------------
static std::string GetSerialNumber(SecCertificateRef cert) {
    CFErrorRef error = nullptr;
    CFDataRef serialData = SecCertificateCopySerialNumberData(cert, &error);
    if (error) {
        if (serialData) CFRelease(serialData);
        CFRelease(error);
        return "";
    }
    if (!serialData) return "";

    const UInt8 *bytes = CFDataGetBytePtr(serialData);
    CFIndex length = CFDataGetLength(serialData);

    std::string hex;
    hex.reserve(length * 2);
    for (CFIndex i = 0; i < length; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", bytes[i]);
        hex += buf;
    }

    CFRelease(serialData);
    return hex;
}

// ---------------------------------------------------------------------------
// Helper: Get certificate validity dates
// ---------------------------------------------------------------------------
static void GetValidityDates(SecCertificateRef cert, std::string &validFrom, std::string &validUntil) {
    validFrom = "";
    validUntil = "";

    // Use SecCertificateCopyValues to extract the validity period
    CFArrayRef keys = nullptr;
    CFStringRef oids[] = {
        kSecOIDX509V1ValidityNotBefore,
        kSecOIDX509V1ValidityNotAfter
    };
    keys = CFArrayCreate(nullptr, (const void **)oids, 2, &kCFTypeArrayCallBacks);

    CFErrorRef error = nullptr;
    CFDictionaryRef values = SecCertificateCopyValues(cert, keys, &error);
    CFRelease(keys);

    if (error) {
        if (values) CFRelease(values);
        CFRelease(error);
        return;
    }
    if (!values) return;

    // Extract NotBefore
    CFDictionaryRef notBeforeDict = (CFDictionaryRef)CFDictionaryGetValue(
        values, kSecOIDX509V1ValidityNotBefore);
    if (notBeforeDict) {
        CFNumberRef notBeforeNum = (CFNumberRef)CFDictionaryGetValue(
            notBeforeDict, kSecPropertyKeyValue);
        if (notBeforeNum) {
            CFAbsoluteTime absTime;
            CFNumberGetValue(notBeforeNum, kCFNumberDoubleType, &absTime);
            CFDateRef date = CFDateCreate(nullptr, absTime);
            if (date) {
                validFrom = CFDateToISO8601(date);
                CFRelease(date);
            }
        }
    }

    // Extract NotAfter
    CFDictionaryRef notAfterDict = (CFDictionaryRef)CFDictionaryGetValue(
        values, kSecOIDX509V1ValidityNotAfter);
    if (notAfterDict) {
        CFNumberRef notAfterNum = (CFNumberRef)CFDictionaryGetValue(
            notAfterDict, kSecPropertyKeyValue);
        if (notAfterNum) {
            CFAbsoluteTime absTime;
            CFNumberGetValue(notAfterNum, kCFNumberDoubleType, &absTime);
            CFDateRef date = CFDateCreate(nullptr, absTime);
            if (date) {
                validUntil = CFDateToISO8601(date);
                CFRelease(date);
            }
        }
    }

    CFRelease(values);
}

// ---------------------------------------------------------------------------
// Helper: Determine key algorithm string from SecKey attributes
// ---------------------------------------------------------------------------
static std::string GetKeyAlgorithmString(SecKeyRef key) {
    CFDictionaryRef attrs = SecKeyCopyAttributes(key);
    if (!attrs) return "";

    CFStringRef keyType = (CFStringRef)CFDictionaryGetValue(attrs, kSecAttrKeyType);
    if (!keyType) {
        CFRelease(attrs);
        return "";
    }

    std::string result;
    if (CFEqual(keyType, kSecAttrKeyTypeECSECPrimeRandom)) {
        CFNumberRef keySizeNum = (CFNumberRef)CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits);
        int keySize = 256;
        if (keySizeNum) {
            CFNumberGetValue(keySizeNum, kCFNumberIntType, &keySize);
        }
        if (keySize == 384) {
            result = "P-384";
        } else {
            result = "P-256";
        }
    } else if (CFEqual(keyType, kSecAttrKeyTypeRSA)) {
        CFNumberRef keySizeNum = (CFNumberRef)CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits);
        int keySize = 2048;
        if (keySizeNum) {
            CFNumberGetValue(keySizeNum, kCFNumberIntType, &keySize);
        }
        result = "RSA-" + std::to_string(keySize);
    }

    CFRelease(attrs);
    return result;
}

// ---------------------------------------------------------------------------
// Helper: Check if a key is exportable
// ---------------------------------------------------------------------------
static bool IsKeyExportable(SecKeyRef key) {
    CFDictionaryRef attrs = SecKeyCopyAttributes(key);
    if (!attrs) return false;

    CFBooleanRef extractable = (CFBooleanRef)CFDictionaryGetValue(attrs, kSecAttrIsExtractable);
    bool result = extractable ? CFBooleanGetValue(extractable) : false;

    CFRelease(attrs);
    return result;
}

// ---------------------------------------------------------------------------
// Helper: Find SecIdentity by thumbprint
// ---------------------------------------------------------------------------
static SecIdentityRef FindIdentityByThumbprint(const std::string &thumbprint) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(query, kSecClass, kSecClassIdentity);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

    CFArrayRef items = nullptr;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&items);
    CFRelease(query);

    if (status != errSecSuccess || !items) return nullptr;

    CFIndex count = CFArrayGetCount(items);
    SecIdentityRef foundIdentity = nullptr;

    for (CFIndex i = 0; i < count; i++) {
        SecIdentityRef identity = (SecIdentityRef)CFArrayGetValueAtIndex(items, i);
        SecCertificateRef cert = nullptr;
        if (SecIdentityCopyCertificate(identity, &cert) != errSecSuccess) continue;

        CFDataRef derData = SecCertificateCopyData(cert);
        if (derData) {
            std::string tp = ComputeThumbprint(derData);
            CFRelease(derData);
            if (tp == thumbprint) {
                CFRetain(identity);
                foundIdentity = identity;
                CFRelease(cert);
                break;
            }
        }
        CFRelease(cert);
    }

    CFRelease(items);
    return foundIdentity;
}

// ---------------------------------------------------------------------------
// Helper: Convert DER-encoded ECDSA signature to raw r||s
// ---------------------------------------------------------------------------
static bool ConvertDerEcdsaToRawRS(const uint8_t *der, size_t derLen,
                                    uint8_t *rawOut, size_t componentLen) {
    // DER: SEQUENCE { INTEGER r, INTEGER s }
    if (derLen < 6 || der[0] != 0x30) return false;

    size_t seqLen = der[1];
    size_t pos = 2;
    if (seqLen > derLen - 2) return false;

    // Parse r
    if (der[pos] != 0x02) return false;
    pos++;
    size_t rLen = der[pos++];
    const uint8_t *rData = der + pos;
    pos += rLen;

    // Parse s
    if (pos >= derLen || der[pos] != 0x02) return false;
    pos++;
    size_t sLen = der[pos++];
    const uint8_t *sData = der + pos;

    // Copy r (strip leading zero padding)
    memset(rawOut, 0, componentLen * 2);
    if (rLen > componentLen) {
        // Leading zero byte for positive integer
        size_t skip = rLen - componentLen;
        memcpy(rawOut + (componentLen - (rLen - skip)), rData + skip, rLen - skip);
    } else {
        memcpy(rawOut + (componentLen - rLen), rData, rLen);
    }

    // Copy s
    if (sLen > componentLen) {
        size_t skip = sLen - componentLen;
        memcpy(rawOut + componentLen + (componentLen - (sLen - skip)), sData + skip, sLen - skip);
    } else {
        memcpy(rawOut + componentLen + (componentLen - sLen), sData, sLen);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Helper: Compress an uncompressed EC point to SEC1 compressed form
// ---------------------------------------------------------------------------
static std::vector<uint8_t> CompressEcPoint(const uint8_t *uncompressed, size_t len) {
    // Uncompressed format: 0x04 || x || y
    // Compressed format: (0x02 if y is even, 0x03 if y is odd) || x
    if (len < 3 || uncompressed[0] != 0x04) {
        // Already compressed or invalid
        return std::vector<uint8_t>(uncompressed, uncompressed + len);
    }

    size_t coordLen = (len - 1) / 2;
    uint8_t prefix = (uncompressed[1 + coordLen + coordLen - 1] & 1) ? 0x03 : 0x02;

    std::vector<uint8_t> compressed(1 + coordLen);
    compressed[0] = prefix;
    memcpy(compressed.data() + 1, uncompressed + 1, coordLen);
    return compressed;
}

// ===========================================================================
// N-API: listSigningCertificates()
// ===========================================================================
static Napi::Value ListSigningCertificates(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(query, kSecClass, kSecClassIdentity);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

    CFArrayRef items = nullptr;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&items);
    CFRelease(query);

    Napi::Array result = Napi::Array::New(env);

    if (status != errSecSuccess || !items) {
        return result; // Empty array if no identities found
    }

    CFIndex count = CFArrayGetCount(items);
    uint32_t resultIdx = 0;

    for (CFIndex i = 0; i < count; i++) {
        SecIdentityRef identity = (SecIdentityRef)CFArrayGetValueAtIndex(items, i);

        // Extract certificate
        SecCertificateRef cert = nullptr;
        if (SecIdentityCopyCertificate(identity, &cert) != errSecSuccess) continue;

        // Extract private key
        SecKeyRef privateKey = nullptr;
        if (SecIdentityCopyPrivateKey(identity, &privateKey) != errSecSuccess) {
            CFRelease(cert);
            continue;
        }

        // Get key algorithm — filter to EC and RSA only
        std::string keyAlgorithm = GetKeyAlgorithmString(privateKey);
        if (keyAlgorithm.empty()) {
            CFRelease(privateKey);
            CFRelease(cert);
            continue;
        }

        // Certificate metadata
        CFStringRef subjectSummary = SecCertificateCopySubjectSummary(cert);
        std::string subject = subjectSummary ? CFStringToStdString(subjectSummary) : "";
        if (subjectSummary) CFRelease(subjectSummary);

        std::string issuer = GetIssuerCN(cert);
        std::string serialNumber = GetSerialNumber(cert);

        std::string validFrom, validUntil;
        GetValidityDates(cert, validFrom, validUntil);

        // Thumbprint
        CFDataRef derData = SecCertificateCopyData(cert);
        std::string thumbprint = derData ? ComputeThumbprint(derData) : "";
        if (derData) CFRelease(derData);

        bool isExportable = IsKeyExportable(privateKey);

        // Build JS object
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

        result.Set(resultIdx++, certObj);

        CFRelease(privateKey);
        CFRelease(cert);
    }

    CFRelease(items);
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

    // Find identity by thumbprint
    CFGuard<SecIdentityRef> identity(FindIdentityByThumbprint(thumbprint));
    if (!identity.get()) {
        Napi::Error::New(env, "Certificate not found in Keychain").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // Get the private key
    SecKeyRef rawPrivateKey = nullptr;
    OSStatus status = SecIdentityCopyPrivateKey(identity, &rawPrivateKey);
    CFGuard<SecKeyRef> privateKey(rawPrivateKey);

    if (status != errSecSuccess || !privateKey.get()) {
        Napi::Error::New(env, "Failed to access private key from Keychain").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // Determine the algorithm from key attributes
    CFGuard<CFDictionaryRef> attrs(SecKeyCopyAttributes(privateKey));
    CFStringRef keyType = attrs.get() ? (CFStringRef)CFDictionaryGetValue(attrs, kSecAttrKeyType) : nullptr;
    CFNumberRef keySizeNum = attrs.get() ? (CFNumberRef)CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits) : nullptr;
    int keySize = 256;
    if (keySizeNum) CFNumberGetValue(keySizeNum, kCFNumberIntType, &keySize);

    SecKeyAlgorithm algorithm;
    bool isEC = false;
    size_t componentLen = 32; // default for P-256

    if (keyType && CFEqual(keyType, kSecAttrKeyTypeECSECPrimeRandom)) {
        isEC = true;
        if (keySize == 384) {
            algorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
            componentLen = 48;
        } else {
            algorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
            componentLen = 32;
        }
    } else {
        algorithm = kSecKeyAlgorithmRSASignatureDigestPSSSHA256;
    }

    // Create CFData from input buffer
    CFGuard<CFDataRef> inputData(CFDataCreate(nullptr, dataBuffer.Data(), dataBuffer.Length()));

    // Sign
    CFErrorRef signError = nullptr;
    CFGuard<CFDataRef> signature(SecKeyCreateSignature(privateKey, algorithm, inputData, &signError));

    if (signError || !signature.get()) {
        if (signError) CFRelease(signError);
        // SECURITY: Do not include error details that might leak key info
        Napi::Error::New(env, "Signing operation failed").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    const uint8_t *sigBytes = CFDataGetBytePtr(signature);
    size_t sigLen = CFDataGetLength(signature);

    Napi::Buffer<uint8_t> resultBuffer;

    if (isEC) {
        // Convert DER ECDSA signature to raw r||s
        std::vector<uint8_t> rawSig(componentLen * 2);
        if (!ConvertDerEcdsaToRawRS(sigBytes, sigLen, rawSig.data(), componentLen)) {
            Napi::Error::New(env, "Failed to convert EC signature format").ThrowAsJavaScriptException();
            return env.Undefined();
        }
        resultBuffer = Napi::Buffer<uint8_t>::Copy(env, rawSig.data(), rawSig.size());
    } else {
        // RSA: return as-is (PKCS#1 v1.5 or PSS)
        resultBuffer = Napi::Buffer<uint8_t>::Copy(env, sigBytes, sigLen);
    }

    return resultBuffer;
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

    // Find identity by thumbprint
    CFGuard<SecIdentityRef> identity(FindIdentityByThumbprint(thumbprint));
    if (!identity.get()) {
        Napi::Error::New(env, "Certificate not found in Keychain").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // Extract certificate
    SecCertificateRef rawCert = nullptr;
    OSStatus status = SecIdentityCopyCertificate(identity, &rawCert);
    CFGuard<SecCertificateRef> cert(rawCert);

    if (status != errSecSuccess || !cert.get()) {
        Napi::Error::New(env, "Failed to extract certificate").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // Get public key from certificate
    CFGuard<SecKeyRef> publicKey(SecCertificateCopyKey(cert));

    if (!publicKey.get()) {
        Napi::Error::New(env, "Failed to extract public key from certificate").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // Determine key type
    CFGuard<CFDictionaryRef> attrs(SecKeyCopyAttributes(publicKey));
    CFStringRef keyType = attrs.get() ? (CFStringRef)CFDictionaryGetValue(attrs, kSecAttrKeyType) : nullptr;
    bool isEC = keyType && CFEqual(keyType, kSecAttrKeyTypeECSECPrimeRandom);

    // Get external representation
    CFErrorRef exportError = nullptr;
    CFGuard<CFDataRef> keyData(SecKeyCopyExternalRepresentation(publicKey, &exportError));

    if (exportError || !keyData.get()) {
        if (exportError) CFRelease(exportError);
        Napi::Error::New(env, "Failed to export public key").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    const uint8_t *keyBytes = CFDataGetBytePtr(keyData);
    size_t keyLen = CFDataGetLength(keyData);

    Napi::Buffer<uint8_t> resultBuffer;

    if (isEC) {
        // SecKeyCopyExternalRepresentation returns the uncompressed point (04 || x || y)
        // Compress it to SEC1 compressed form
        std::vector<uint8_t> compressed = CompressEcPoint(keyBytes, keyLen);
        resultBuffer = Napi::Buffer<uint8_t>::Copy(env, compressed.data(), compressed.size());
    } else {
        // RSA: SecKeyCopyExternalRepresentation returns PKCS#1 format.
        // We need to wrap it in SPKI DER for the TypeScript layer.
        // Build SPKI: SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { pkcs1Key } }

        // RSA OID: 1.2.840.113549.1.1.1
        static const uint8_t rsaOidAndNull[] = {
            0x30, 0x0d, // SEQUENCE (13 bytes)
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID
            0x05, 0x00  // NULL
        };

        // BIT STRING wrapper: 0x03, length, 0x00 (no unused bits), keyData
        size_t bitStringContentLen = 1 + keyLen; // 0x00 prefix + key data
        std::vector<uint8_t> spki;

        // Encode BIT STRING length
        std::vector<uint8_t> bitStringHeader;
        bitStringHeader.push_back(0x03);
        if (bitStringContentLen < 128) {
            bitStringHeader.push_back((uint8_t)bitStringContentLen);
        } else if (bitStringContentLen < 256) {
            bitStringHeader.push_back(0x81);
            bitStringHeader.push_back((uint8_t)bitStringContentLen);
        } else {
            bitStringHeader.push_back(0x82);
            bitStringHeader.push_back((uint8_t)(bitStringContentLen >> 8));
            bitStringHeader.push_back((uint8_t)(bitStringContentLen & 0xFF));
        }

        // Total inner content: algorithmIdentifier + bitString
        size_t innerLen = sizeof(rsaOidAndNull) + bitStringHeader.size() + bitStringContentLen;

        // Outer SEQUENCE header
        spki.push_back(0x30);
        if (innerLen < 128) {
            spki.push_back((uint8_t)innerLen);
        } else if (innerLen < 256) {
            spki.push_back(0x81);
            spki.push_back((uint8_t)innerLen);
        } else {
            spki.push_back(0x82);
            spki.push_back((uint8_t)(innerLen >> 8));
            spki.push_back((uint8_t)(innerLen & 0xFF));
        }

        // Algorithm identifier
        spki.insert(spki.end(), rsaOidAndNull, rsaOidAndNull + sizeof(rsaOidAndNull));

        // BIT STRING
        spki.insert(spki.end(), bitStringHeader.begin(), bitStringHeader.end());
        spki.push_back(0x00); // no unused bits
        spki.insert(spki.end(), keyBytes, keyBytes + keyLen);

        resultBuffer = Napi::Buffer<uint8_t>::Copy(env, spki.data(), spki.size());
    }

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

    // Find identity by thumbprint
    CFGuard<SecIdentityRef> identity(FindIdentityByThumbprint(thumbprint));
    if (!identity.get()) {
        return Napi::Array::New(env); // Empty array if not found
    }

    // Extract certificate
    SecCertificateRef rawCert = nullptr;
    OSStatus status = SecIdentityCopyCertificate(identity, &rawCert);
    CFGuard<SecCertificateRef> cert(rawCert);

    if (status != errSecSuccess || !cert.get()) {
        return Napi::Array::New(env);
    }

    // Build a trust object and evaluate the chain
    CFGuard<SecPolicyRef> policy(SecPolicyCreateBasicX509());
    SecTrustRef rawTrust = nullptr;
    status = SecTrustCreateWithCertificates(cert, policy, &rawTrust);
    CFGuard<SecTrustRef> trust(rawTrust);

    if (status != errSecSuccess || !trust.get()) {
        return Napi::Array::New(env);
    }

    CFErrorRef evalError = nullptr;
    bool trusted = SecTrustEvaluateWithError(trust, &evalError);
    if (evalError) CFRelease(evalError);
    (void)trusted; // We want the chain even if not fully trusted

    CFIndex chainLen = SecTrustGetCertificateCount(trust);
    Napi::Array result = Napi::Array::New(env);

    for (CFIndex i = 0; i < chainLen; i++) {
        SecCertificateRef chainCert = SecTrustGetCertificateAtIndex(trust, i);
        if (!chainCert) continue;

        CFGuard<CFDataRef> derData(SecCertificateCopyData(chainCert));
        if (!derData.get()) continue;

        const uint8_t *bytes = CFDataGetBytePtr(derData);
        size_t len = CFDataGetLength(derData);

        // Base64 encode for PEM
        NSData *nsData = [NSData dataWithBytes:bytes length:len];
        NSString *base64 = [nsData base64EncodedStringWithOptions:
            NSDataBase64Encoding76CharacterLineLength];

        std::string pem = "-----BEGIN CERTIFICATE-----\n";
        pem += [base64 UTF8String];
        pem += "\n-----END CERTIFICATE-----";

        result.Set((uint32_t)i, pem);
    }

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

NODE_API_MODULE(macos_keychain, Init)
