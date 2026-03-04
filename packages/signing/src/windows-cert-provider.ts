/**
 * Windows certificate store provider.
 *
 * Interfaces with Windows CNG (Cryptography API: Next Generation) for
 * certificate enumeration and signing with Windows-managed keys. The
 * private key never leaves the Windows certificate store — all signing
 * is performed by CNG/CryptoAPI.
 *
 * NATIVE ADDON REQUIRED:
 * The actual Windows CNG calls require an N-API native addon that binds
 * to the following Windows APIs:
 *
 *   - CertOpenStore()         — open the "MY" certificate store
 *   - CertEnumCertificatesInStore() — enumerate certificates
 *   - CertGetCertificateContextProperty() — get key info
 *   - CryptAcquireCertificatePrivateKey() — acquire key handle
 *   - NCryptSignHash()        — sign a hash with a CNG key
 *   - CertFreeCertificateContext() — release certificate context
 *   - CertCloseStore()        — close the store
 *
 * Key CNG types and constants:
 *   - NCRYPT_KEY_HANDLE       — opaque handle to a CNG key
 *   - BCRYPT_ECDSA_P256_ALGORITHM — algorithm identifier for P-256 ECDSA
 *   - CERT_KEY_PROV_INFO_PROP_ID — property ID for key provider info
 *   - NCRYPT_ALLOW_EXPORT_FLAG — check if key is exportable
 *
 * The native addon function signatures (for N-API binding):
 *
 *   napi_value ListSigningCertificates(napi_env env, napi_callback_info info)
 *     — Returns: Array<{ id, subject, issuer, serialNumber, validFrom,
 *       validUntil, keyAlgorithm, isExportable, thumbprint }>
 *     — Opens: CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
 *              CERT_SYSTEM_STORE_CURRENT_USER, L"MY")
 *     — Filters for: szOID_ECC_PUBLIC_KEY + P-256 curves
 *     — Uses thumbprint (SHA-256 of DER cert) as the certificate ID
 *
 *   napi_value SignWithCertificate(napi_env env, napi_callback_info info)
 *     — Args: (certificateId: string, data: Buffer)
 *     — Returns: Buffer (raw r||s signature, 64 bytes)
 *     — Uses: CryptAcquireCertificatePrivateKey -> NCryptSignHash
 *     — Padding: BCRYPT_PAD_NONE (ECDSA on pre-hashed data)
 *     — The digest is computed in JS; CNG signs the hash.
 *
 *   napi_value GetPublicKey(napi_env env, napi_callback_info info)
 *     — Args: (certificateId: string)
 *     — Returns: Buffer (SEC1 compressed public key, 33 bytes)
 *     — Extracts from: CERT_CONTEXT.pCertInfo->SubjectPublicKeyInfo
 *
 * SECURITY INVARIANTS:
 *  - The private key NEVER leaves the Windows certificate store / CNG.
 *  - No key material is logged. Only certificate metadata and thumbprints.
 *  - The native addon must not expose any function that exports private keys.
 *  - Windows may prompt for consent (e.g., smart card PIN, strong key
 *    protection dialog) — this is handled by CNG/CryptoAPI.
 */

import { createRequire } from "node:module";
import { CryptoError } from "@opencred/shared";
import type { OsCertProvider, OsCertInfo } from "./os-cert-types.js";

const require = createRequire(import.meta.url);

/**
 * Interface for the native Windows CNG addon module.
 *
 * When a real N-API addon is built, it should export these functions.
 * The function signatures correspond to the CNG/CryptoAPI calls
 * documented above.
 */
export interface WindowsNativeAddon {
  /**
   * List signing certificates from the Windows "MY" certificate store.
   * Includes EC (P-256, P-384) and RSA certificates with signing capability.
   */
  listSigningCertificates(): OsCertInfo[];

  /**
   * Sign data with a CNG-managed private key.
   * @param certificateId - The certificate thumbprint (SHA-256, hex).
   * @param data - Hash of the data to sign.
   * @returns Raw signature bytes (r||s for EC, RSASSA-PSS for RSA).
   */
  signWithCertificate(certificateId: string, data: Buffer): Buffer;

  /**
   * Get the public key from a certificate.
   * For EC keys: SEC1 compressed public key (33 bytes for P-256, 49 for P-384).
   * For RSA keys: SPKI DER-encoded public key.
   * @param certificateId - The certificate thumbprint (SHA-256, hex).
   * @returns Public key bytes.
   */
  getPublicKey(certificateId: string): Buffer;

  /**
   * Get the certificate chain (PEM-encoded) for a certificate.
   * Optional — only available when the addon supports chain extraction.
   * @param certificateId - The certificate thumbprint (SHA-256, hex).
   * @returns Array of PEM-encoded certificates (DSC first, then intermediates).
   */
  getCertificateChain?(certificateId: string): string[];
}

/**
 * Attempt to load the native Windows addon.
 *
 * Returns null if the addon is not available (e.g., not built yet,
 * running on a non-Windows platform, or in a test environment).
 */
function loadNativeAddon(): WindowsNativeAddon | null {
  try {
    // The native addon will be at this path when built with node-gyp.
    const addon = require("../../native/build/Release/windows-cng.node") as WindowsNativeAddon;
    if (
      typeof addon.listSigningCertificates === "function" &&
      typeof addon.signWithCertificate === "function" &&
      typeof addon.getPublicKey === "function"
    ) {
      return addon;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Create a Windows certificate store provider.
 *
 * If the native addon is available, uses real Windows CNG integration.
 * Otherwise, throws CryptoError indicating the native addon is required.
 *
 * @param nativeAddon - Optional override for the native addon (used in tests).
 * @returns OsCertProvider for Windows CNG operations.
 */
export function createWindowsCertProvider(nativeAddon?: WindowsNativeAddon | null): OsCertProvider {
  const addon = nativeAddon !== undefined ? nativeAddon : loadNativeAddon();

  const provider: OsCertProvider = {
    async listCertificates(): Promise<OsCertInfo[]> {
      if (!addon) {
        throw new CryptoError(
          "Windows CNG native addon is not available. " +
            "Build the native addon for Windows Certificate Store integration, " +
            "or use a software key or PKCS#11 token instead.",
        );
      }

      try {
        return addon.listSigningCertificates();
      } catch {
        throw new CryptoError("Failed to enumerate Windows Certificate Store certificates");
      }
    },

    async sign(certificateId: string, data: Uint8Array): Promise<Uint8Array> {
      if (!addon) {
        throw new CryptoError("Windows CNG native addon is not available");
      }

      if (!certificateId) {
        throw new CryptoError("Certificate ID is required for signing");
      }

      try {
        const result = addon.signWithCertificate(certificateId, Buffer.from(data));
        const signature = new Uint8Array(result);

        if (signature.length === 0) {
          throw new CryptoError("Windows CNG returned an empty signature");
        }

        return signature;
      } catch (error) {
        if (error instanceof CryptoError) throw error;
        throw new CryptoError("Windows CNG signing operation failed");
      }
    },

    async getPublicKey(certificateId: string): Promise<Uint8Array> {
      if (!addon) {
        throw new CryptoError("Windows CNG native addon is not available");
      }

      if (!certificateId) {
        throw new CryptoError("Certificate ID is required");
      }

      try {
        const result = addon.getPublicKey(certificateId);
        const publicKey = new Uint8Array(result);

        if (publicKey.length === 0) {
          throw new CryptoError("Windows CNG returned an empty public key");
        }

        return publicKey;
      } catch (error) {
        if (error instanceof CryptoError) throw error;
        throw new CryptoError("Failed to extract public key from Windows certificate");
      }
    },

    async getCertificateChain(certificateId: string): Promise<string[]> {
      if (!addon?.getCertificateChain) {
        return [];
      }
      try {
        return addon.getCertificateChain(certificateId);
      } catch {
        return [];
      }
    },
  };

  return provider;
}
