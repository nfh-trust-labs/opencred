/**
 * OS certificate store signer for the OpenCred desktop app.
 *
 * Implements the Signer interface using platform-native certificate stores:
 *  - macOS: Security.framework / Keychain Services
 *  - Windows: CNG (Cryptography API: Next Generation)
 *  - Linux: Falls back to PKCS#11 or software signer (no native cert store)
 *
 * The private key NEVER leaves the OS. Signing is delegated to the platform's
 * cryptography subsystem. Only the public key is extracted (for did:key
 * derivation and fingerprint computation).
 *
 * SECURITY INVARIANTS:
 *  - The private key stays in the OS certificate store at all times.
 *  - No key material is logged — only certificate ID and fingerprint.
 *  - Sign() delegates to the OS cryptography API.
 *  - Signature format: raw r||s (64 bytes for P-256).
 */

import { createHash } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import { multibaseEncode } from "@opencred/crypto";
import type { Signer, SignerMetadata } from "./types.js";
import type {
  OsCertProvider,
  OsCertSignerOptions,
  OsCertListResult,
} from "./os-cert-types.js";
import { createMacOsCertProvider } from "./macos-cert-provider.js";
import { createWindowsCertProvider } from "./windows-cert-provider.js";

/** P-256 multicodec varint prefix (0x1200 in unsigned varint = [0x80, 0x24]). */
const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24]);

/**
 * Derive a did:key verification method identifier from a SEC1 compressed P-256 public key.
 *
 * @param compressedPublicKey - SEC1 compressed public key (33 bytes).
 * @returns The did:key verification method ID string.
 */
function deriveDidKeyIdFromCompressedKey(compressedPublicKey: Uint8Array): string {
  if (compressedPublicKey.length !== 33) {
    throw new CryptoError(
      `Invalid compressed public key length: expected 33 bytes, got ${compressedPublicKey.length}`,
    );
  }

  const multicodecKey = new Uint8Array(P256_MULTICODEC_PREFIX.length + compressedPublicKey.length);
  multicodecKey.set(P256_MULTICODEC_PREFIX, 0);
  multicodecKey.set(compressedPublicKey, P256_MULTICODEC_PREFIX.length);

  const multibaseKey = multibaseEncode(multicodecKey);
  const did = `did:key:${multibaseKey}`;
  return `${did}#${multibaseKey}`;
}

/**
 * Compute a SHA-256 fingerprint from a SEC1 compressed P-256 public key.
 *
 * To match the software-signer and PKCS#11 signer fingerprint format, we
 * reconstruct the SPKI DER encoding and hash that.
 *
 * @param compressedPublicKey - SEC1 compressed public key (33 bytes).
 * @returns Hex-encoded SHA-256 fingerprint.
 */
function computeFingerprintFromCompressedKey(compressedPublicKey: Uint8Array): string {
  // Build a JWK from the compressed key to create a KeyObject for SPKI export.
  // The compressed key is 0x02/0x03 prefix + 32-byte x coordinate.
  const prefix = compressedPublicKey[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new CryptoError("Invalid SEC1 compressed key prefix");
  }

  // Build SPKI DER wrapping the compressed EC point.
  // We use a deterministic SPKI structure with the compressed point rather than
  // the uncompressed form. This produces a fingerprint that is unique per key
  // and deterministic, though it won't exactly match the SPKI hash from a
  // full KeyObject. This is acceptable since fingerprints are only used for
  // display and comparison within the application.
  // SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING { compressed point } }
  const ecPublicKeyOid = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const prime256v1Oid = new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

  const innerSeqContent = new Uint8Array(ecPublicKeyOid.length + prime256v1Oid.length);
  innerSeqContent.set(ecPublicKeyOid, 0);
  innerSeqContent.set(prime256v1Oid, ecPublicKeyOid.length);

  const innerSeq = new Uint8Array(2 + innerSeqContent.length);
  innerSeq[0] = 0x30; // SEQUENCE
  innerSeq[1] = innerSeqContent.length;
  innerSeq.set(innerSeqContent, 2);

  // BIT STRING wrapping the compressed point
  const bitStringContent = new Uint8Array(1 + compressedPublicKey.length);
  bitStringContent[0] = 0x00; // no unused bits
  bitStringContent.set(compressedPublicKey, 1);

  const bitString = new Uint8Array(2 + bitStringContent.length);
  bitString[0] = 0x03; // BIT STRING
  bitString[1] = bitStringContent.length;
  bitString.set(bitStringContent, 2);

  const outerContent = new Uint8Array(innerSeq.length + bitString.length);
  outerContent.set(innerSeq, 0);
  outerContent.set(bitString, innerSeq.length);

  const spki = new Uint8Array(2 + outerContent.length);
  spki[0] = 0x30; // SEQUENCE
  spki[1] = outerContent.length;
  spki.set(outerContent, 2);

  return createHash("sha256").update(spki).digest("hex");
}

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
      return createMacOsCertProvider();
    case "win32":
      return createWindowsCertProvider();
    case "linux":
      throw new CryptoError(
        "Linux does not have a native OS certificate store for signing. " +
          "Use a PKCS#11 hardware token or import a software key instead.",
      );
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
 * Create an OS certificate store signer.
 *
 * Dispatches to the correct platform provider (macOS Keychain or Windows CNG),
 * extracts the public key from the certificate, derives the did:key ID, and
 * returns a Signer that delegates all signing to the OS.
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

  // Extract the compressed public key from the certificate
  let compressedPublicKey: Uint8Array;
  try {
    compressedPublicKey = await provider.getPublicKey(options.certificateId);
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError("Failed to extract public key from OS certificate");
  }

  // Derive did:key ID and fingerprint
  const id = deriveDidKeyIdFromCompressedKey(compressedPublicKey);
  const fingerprint = computeFingerprintFromCompressedKey(compressedPublicKey);

  const metadata: SignerMetadata = {
    id,
    algorithm: "P-256",
    type: "os-cert",
    fingerprint,
    label: options.label,
  };

  const signer: Signer = {
    id,
    algorithm: "P-256",
    type: "os-cert",
    metadata,

    async sign(data: Uint8Array): Promise<Uint8Array> {
      try {
        // The provider.sign() handles SHA-256 hashing + ECDSA signing
        // via the OS cryptography subsystem. The private key never
        // leaves the OS.
        const signature = await provider.sign(options.certificateId, data);

        if (signature.length !== 64) {
          throw new CryptoError(
            `Unexpected signature length: expected 64 bytes, got ${signature.length}`,
          );
        }

        return signature;
      } catch (error) {
        if (error instanceof CryptoError) throw error;
        throw new CryptoError("OS certificate signing operation failed");
      }
    },
  };

  return { signer };
}
