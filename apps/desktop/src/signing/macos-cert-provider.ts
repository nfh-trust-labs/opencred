/**
 * macOS certificate store provider.
 *
 * Interfaces with macOS Security.framework / Keychain Services for certificate
 * enumeration and signing with Keychain-managed keys. The private key never
 * leaves the macOS Keychain — all signing is performed by the OS.
 *
 * NATIVE ADDON REQUIRED:
 * The actual macOS Security.framework calls require an N-API native addon that
 * binds to the following Security.framework functions:
 *
 *   - SecItemCopyMatching()   — enumerate certificates/keys in Keychain
 *   - SecKeyCreateSignature() — sign data using a Keychain-managed key
 *   - SecKeyCopyPublicKey()   — extract the public key from a key reference
 *   - SecCertificateCopyData() — export certificate DER for thumbprint
 *   - SecCertificateCopySubjectSummary() — get the subject CN
 *
 * The native addon function signatures (for N-API binding):
 *
 *   napi_value ListSigningCertificates(napi_env env, napi_callback_info info)
 *     — Returns: Array<{ id, subject, issuer, serialNumber, validFrom,
 *       validUntil, keyAlgorithm, isExportable, thumbprint }>
 *     — Queries: kSecClassCertificate + kSecAttrCanSign
 *     — Filters for: kSecAttrKeyTypeECSECPrimeRandom (P-256)
 *
 *   napi_value SignWithCertificate(napi_env env, napi_callback_info info)
 *     — Args: (certificateId: string, data: Buffer)
 *     — Returns: Buffer (raw r||s signature, 64 bytes)
 *     — Uses: SecKeyCreateSignature with kSecAlgorithmECDSASignatureDigestX962SHA256
 *     — The digest is computed in JS; Security.framework signs the hash.
 *
 *   napi_value GetPublicKey(napi_env env, napi_callback_info info)
 *     — Args: (certificateId: string)
 *     — Returns: Buffer (SEC1 compressed public key, 33 bytes)
 *     — Uses: SecKeyCopyPublicKey + SecKeyCopyExternalRepresentation
 *
 * SECURITY INVARIANTS:
 *  - The private key NEVER leaves the macOS Keychain.
 *  - No key material is logged. Only certificate metadata and thumbprints.
 *  - The native addon must not expose any function that exports private keys.
 *  - Keychain access prompts are handled by macOS (the user may need to
 *    authorize access via Touch ID or password).
 */

import { CryptoError } from "@opencred/shared";
import type { OsCertProvider, OsCertInfo } from "./os-cert-types.js";

/**
 * Interface for the native macOS addon module.
 *
 * When a real N-API addon is built, it should export these functions.
 * The function signatures correspond to the Security.framework calls
 * documented above.
 */
export interface MacOsNativeAddon {
  /**
   * List signing certificates from macOS Keychain.
   * Filters for EC P-256 certificates with signing capability.
   */
  listSigningCertificates(): OsCertInfo[];

  /**
   * Sign data with a Keychain-managed private key.
   * @param certificateId - The Keychain persistent reference identifier.
   * @param data - SHA-256 hash of the data to sign (32 bytes).
   * @returns Raw r||s signature (64 bytes for P-256).
   */
  signWithCertificate(certificateId: string, data: Buffer): Buffer;

  /**
   * Get the SEC1 compressed public key from a certificate.
   * @param certificateId - The Keychain persistent reference identifier.
   * @returns SEC1 compressed public key (33 bytes for P-256).
   */
  getPublicKey(certificateId: string): Buffer;
}

/**
 * Attempt to load the native macOS addon.
 *
 * Returns null if the addon is not available (e.g., not built yet,
 * running on a different platform, or in a test environment).
 */
function loadNativeAddon(): MacOsNativeAddon | null {
  try {
    // The native addon will be at this path when built with node-gyp.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const addon = require("../native/macos-keychain.node") as MacOsNativeAddon;
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
 * Create a macOS certificate store provider.
 *
 * If the native addon is available, uses real macOS Keychain integration.
 * Otherwise, throws CryptoError indicating the native addon is required.
 *
 * @param nativeAddon - Optional override for the native addon (used in tests).
 * @returns OsCertProvider for macOS Keychain operations.
 */
export function createMacOsCertProvider(nativeAddon?: MacOsNativeAddon | null): OsCertProvider {
  const addon = nativeAddon !== undefined ? nativeAddon : loadNativeAddon();

  const provider: OsCertProvider = {
    async listCertificates(): Promise<OsCertInfo[]> {
      if (!addon) {
        throw new CryptoError(
          "macOS Keychain native addon is not available. " +
            "Build the native addon for Security.framework integration, " +
            "or use a software key or PKCS#11 token instead.",
        );
      }

      try {
        return addon.listSigningCertificates();
      } catch {
        throw new CryptoError("Failed to enumerate macOS Keychain certificates");
      }
    },

    async sign(certificateId: string, data: Uint8Array): Promise<Uint8Array> {
      if (!addon) {
        throw new CryptoError("macOS Keychain native addon is not available");
      }

      if (!certificateId) {
        throw new CryptoError("Certificate ID is required for signing");
      }

      try {
        const result = addon.signWithCertificate(certificateId, Buffer.from(data));
        const signature = new Uint8Array(result);

        if (signature.length !== 64) {
          throw new CryptoError(
            `Unexpected signature length from macOS Keychain: expected 64 bytes, got ${signature.length}`,
          );
        }

        return signature;
      } catch (error) {
        if (error instanceof CryptoError) throw error;
        throw new CryptoError("macOS Keychain signing operation failed");
      }
    },

    async getPublicKey(certificateId: string): Promise<Uint8Array> {
      if (!addon) {
        throw new CryptoError("macOS Keychain native addon is not available");
      }

      if (!certificateId) {
        throw new CryptoError("Certificate ID is required");
      }

      try {
        const result = addon.getPublicKey(certificateId);
        const publicKey = new Uint8Array(result);

        if (publicKey.length !== 33) {
          throw new CryptoError(
            `Unexpected public key length from macOS Keychain: expected 33 bytes, got ${publicKey.length}`,
          );
        }

        return publicKey;
      } catch (error) {
        if (error instanceof CryptoError) throw error;
        throw new CryptoError("Failed to extract public key from macOS Keychain certificate");
      }
    },
  };

  return provider;
}
