/**
 * OS certificate store signer for the OpenCred desktop app.
 *
 * Implements the Signer interface using platform-native certificate stores:
 *  - macOS: Security.framework / Keychain Services
 *  - Windows: CNG (Cryptography API: Next Generation)
 *  - Linux: Falls back to PKCS#11 or software signer (no native cert store)
 *
 * The private key NEVER leaves the OS. Signing is delegated to the platform's
 * cryptography subsystem. Only the public key is extracted (for DID derivation
 * and fingerprint computation).
 *
 * SECURITY INVARIANTS:
 *  - The private key stays in the OS certificate store at all times.
 *  - No key material is logged — only certificate ID and fingerprint.
 *  - Sign() delegates to the OS cryptography API.
 *  - EC signatures: raw r||s (64 bytes for P-256, 96 bytes for P-384).
 *  - RSA signatures: RSASSA-PSS (variable length depending on modulus).
 */

import { createPublicKey } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import { publicKeyFromEcBytes, sha256, sha384, type SigningAlgorithm } from "@opencred/crypto";
import {
  deriveDidKeyIdFromCompressedKey,
  computeKeyFingerprint,
  encodeDidJwk,
  didJwkVerificationMethodId,
  type JWK,
} from "@opencred/did";
import type { Signer, SignerMetadata } from "./types.js";
import type { OsCertProvider, OsCertSignerOptions, OsCertListResult } from "./os-cert-types.js";
import { createMacOsCertProvider } from "./macos-cert-provider.js";
import { createWindowsCertProvider } from "./windows-cert-provider.js";
import { autoDiscoverP11KitModule } from "./p11-kit-discovery.js";

/**
 * Expected raw signature lengths for EC algorithms.
 * RSA signature length varies — we only check > 0.
 */
const EC_SIGNATURE_LENGTHS: Record<string, number> = {
  "P-256": 64,
  "P-384": 96,
};

/**
 * Get the OS cert provider for the specified platform.
 *
 * @param platform - The runtime platform.
 * @param providerOverride - Optional provider override (for tests).
 * @returns The platform-specific OsCertProvider.
 * @throws {CryptoError} if the platform is not supported.
 */
export function getProviderForPlatform(
  platform: "darwin" | "win32" | "linux",
  providerOverride?: OsCertProvider,
): OsCertProvider {
  if (providerOverride) {
    return providerOverride;
  }

  switch (platform) {
    case "darwin":
      if (process.platform !== "darwin") {
        throw new CryptoError(
          "macOS Keychain integration is only available on macOS. " +
            `Current platform: ${process.platform}. ` +
            "Use a software key or PKCS#11 token instead.",
        );
      }
      return createMacOsCertProvider();
    case "win32":
      if (process.platform !== "win32") {
        throw new CryptoError(
          "Windows Certificate Store integration is only available on Windows. " +
            `Current platform: ${process.platform}. ` +
            "Use a software key or PKCS#11 token instead.",
        );
      }
      return createWindowsCertProvider();
    case "linux": {
      const p11Module = autoDiscoverP11KitModule();
      const hint = p11Module
        ? ` p11-kit-proxy detected at ${p11Module} — use the PKCS#11 signer with this module path.`
        : " Install p11-kit for automatic PKCS#11 module discovery, or specify a module path manually.";
      throw new CryptoError(
        "Linux does not have a native OS certificate store for signing." +
          hint +
          " Alternatively, import a software key.",
      );
    }
    default:
      throw new CryptoError(
        `Unsupported platform for OS certificate store signing: ${platform as string}`,
      );
  }
}

/**
 * List certificates from the OS certificate store.
 *
 * @param platform - The runtime platform.
 * @param providerOverride - Optional provider override (for tests).
 * @returns Certificate list with platform metadata.
 */
export async function listOsCertificates(
  platform: "darwin" | "win32" | "linux",
  providerOverride?: OsCertProvider,
): Promise<OsCertListResult> {
  const storeNames: Record<string, string> = {
    darwin: "macOS Keychain",
    win32: "Windows Certificate Store",
    linux: "Linux (no native store)",
  };

  const provider = getProviderForPlatform(platform, providerOverride);
  const certificates = await provider.listCertificates();

  return {
    certificates,
    platform,
    storeName: storeNames[platform] ?? "Unknown",
  };
}

/**
 * Derive the DID identifier and fingerprint for an EC key from its compressed form.
 */
function deriveEcIdentity(
  compressedPublicKey: Uint8Array,
  curve: "P-256" | "P-384",
): { id: string; fingerprint: string } {
  const id = deriveDidKeyIdFromCompressedKey(compressedPublicKey, curve);

  // Build a KeyObject from the compressed key so we can compute a standard fingerprint
  const ecPublicKey = publicKeyFromEcBytes(compressedPublicKey);
  const fingerprint = computeKeyFingerprint(ecPublicKey);

  return { id, fingerprint };
}

/**
 * Derive the DID identifier and fingerprint for an RSA key from SPKI DER bytes.
 */
function deriveRsaIdentity(spkiDer: Uint8Array): { id: string; fingerprint: string } {
  const publicKey = createPublicKey({
    key: Buffer.from(spkiDer),
    format: "der",
    type: "spki",
  });

  const jwk = publicKey.export({ format: "jwk" }) as JWK;
  const did = encodeDidJwk(jwk);
  const id = didJwkVerificationMethodId(did);
  const fingerprint = computeKeyFingerprint(publicKey);

  return { id, fingerprint };
}

/**
 * Validate a signature based on the signing algorithm.
 *
 * EC signatures must match exact expected lengths.
 * RSA signatures must be non-empty.
 */
function validateSignatureLength(signature: Uint8Array, algorithm: SigningAlgorithm): void {
  if (signature.length === 0) {
    throw new CryptoError("OS certificate signing returned an empty signature");
  }

  const expectedEcLength = EC_SIGNATURE_LENGTHS[algorithm];
  if (expectedEcLength !== undefined && signature.length !== expectedEcLength) {
    throw new CryptoError(
      `Unexpected signature length: expected ${expectedEcLength} bytes, got ${signature.length}`,
    );
  }
}

/**
 * Create an OS certificate store signer.
 *
 * Dispatches to the correct platform provider (macOS Keychain or Windows CNG),
 * extracts the public key from the certificate, derives the DID identifier,
 * and returns a Signer that delegates all signing to the OS.
 *
 * For EC keys (P-256, P-384): uses did:key with multicodec encoding.
 * For RSA keys: uses did:jwk with JWK base64url encoding.
 *
 * @param options - Signer creation options.
 * @param providerOverride - Optional provider override (for tests).
 * @returns An object containing the Signer.
 * @throws {CryptoError} on platform not supported, native addon missing, or
 *         certificate not found.
 */
export async function createOsCertSigner(
  options: OsCertSignerOptions,
  providerOverride?: OsCertProvider,
): Promise<{ signer: Signer }> {
  const provider = getProviderForPlatform(options.platform, providerOverride);
  const algorithm: SigningAlgorithm = options.keyAlgorithm ?? "P-256";

  // Extract the public key from the certificate
  let publicKeyBytes: Uint8Array;
  try {
    publicKeyBytes = await provider.getPublicKey(options.certificateId);
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError("Failed to extract public key from OS certificate");
  }

  // Derive DID and fingerprint based on algorithm
  let id: string;
  let fingerprint: string;

  if (algorithm.startsWith("RSA")) {
    // RSA: public key is SPKI DER → did:jwk
    ({ id, fingerprint } = deriveRsaIdentity(publicKeyBytes));
  } else {
    // EC: public key is SEC1 compressed → did:key
    const curve = algorithm as "P-256" | "P-384";
    ({ id, fingerprint } = deriveEcIdentity(publicKeyBytes, curve));
  }

  // Get certificate chain if the provider supports it
  let certificateChain: string[] | undefined;
  if (provider.getCertificateChain) {
    try {
      const chain = await provider.getCertificateChain(options.certificateId);
      if (chain.length > 0) {
        certificateChain = chain;
      }
    } catch {
      // Certificate chain is optional — failure is non-fatal
    }
  }

  const metadata: SignerMetadata = {
    id,
    algorithm,
    type: "os-cert",
    fingerprint,
    label: options.label,
    certificateChain,
  };

  const signer: Signer = {
    id,
    algorithm,
    type: "os-cert",
    metadata,

    async sign(data: Uint8Array): Promise<Uint8Array> {
      // The caller (`prepareProof` for Data Integrity, `createJwsSignature`
      // for VC-JWT, etc.) passes the *message* bytes — for P-256 this is
      // the 64-byte concat of sha256(proofConfig)||sha256(document); for
      // P-384, 96 bytes with SHA-384. Native cert-store addons on both
      // macOS and Windows use the "Digest" signing variants
      // (`kSecKeyAlgorithmECDSASignatureDigestX962SHA256/384`,
      // `NCryptSignHash`) which require the caller to supply the digest.
      // Hash here, matching the contract PKCS#11 and software signers
      // already honor; the resulting ECDSA(sha256/sha384(data)) verifies
      // against the verifier's `createVerify(...).update(data).verify(...)`
      // pipeline unchanged.
      const digest =
        algorithm === "P-384"
          ? sha384(data)
          : algorithm === "P-256"
            ? sha256(data)
            : // RSA OS-cert signing uses PSS + SHA-256 in the addon
              sha256(data);
      try {
        const signature = await provider.sign(options.certificateId, digest);
        validateSignatureLength(signature, algorithm);
        return signature;
      } catch (error) {
        if (error instanceof CryptoError) throw error;
        throw new CryptoError("OS certificate signing operation failed");
      }
    },
  };

  return { signer };
}
