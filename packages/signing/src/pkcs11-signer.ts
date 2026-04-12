/**
 * PKCS#11 signer for the OpenCred desktop app.
 *
 * Implements the Signer interface using a hardware token via PKCS#11.
 * The private key NEVER leaves the hardware token — all signing operations
 * are performed on-device via C_Sign. Only the public key is extracted
 * for DID derivation and metadata.
 *
 * SECURITY INVARIANTS:
 *  - The private key stays on the hardware token at all times.
 *  - The PIN is used for session login only and is never stored.
 *  - No key material is logged. Only the key fingerprint and DID ID
 *    appear in metadata.
 *  - Sessions are always closed in a finally block.
 *  - EC signature format: CKM_ECDSA returns raw r||s (64 bytes for P-256,
 *    96 bytes for P-384). Some tokens may return DER — normalizeSignature
 *    handles conversion.
 *  - RSA signature format: CKM_RSA_PKCS_PSS returns RSASSA-PSS signature.
 */

import { createHash } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import type * as Pkcs11Types from "pkcs11js";
import { loadPkcs11js } from "./pkcs11-loader.js";

/**
 * Lazy accessor for the pkcs11js module.
 * See pkcs11-loader.ts for rationale.
 */
const pkcs11js: typeof Pkcs11Types = new Proxy({} as typeof Pkcs11Types, {
  get(_target, prop: string) {
    return (loadPkcs11js() as Record<string, unknown>)[prop];
  },
});

import { encodeDidJwk, didJwkVerificationMethodId } from "@opencred/did";
import type { SigningAlgorithm } from "@opencred/crypto";
import type { Signer, SignerMetadata } from "./types.js";
import {
  initializePkcs11,
  finalizePkcs11,
  openSession,
  closeSession,
  listKeys,
  listCertificates,
  findPrivateKey,
  type Pkcs11Session,
  type Pkcs11KeyInfo,
} from "./pkcs11-session.js";
import {
  publicKeyFromEcPoint,
  publicKeyFromRsaComponents,
  rsaAlgorithmFromModulusBits,
  normalizeSignature,
  derCertToPem,
} from "./pkcs11-utils.js";
import { deriveDidKeyId, computeKeyFingerprint } from "@opencred/did";

/**
 * Options for creating a PKCS#11 signer.
 */
export interface Pkcs11SignerOptions {
  /** Absolute path to the PKCS#11 shared library (.so/.dll/.dylib). */
  libraryPath: string;
  /** Slot index (default: 0). */
  slotIndex?: number;
  /** Token PIN — entered by user, never stored. */
  pin: string;
  /** Hex-encoded CKA_ID of the key to use. If not provided, uses first available key. */
  keyId?: string;
  /** Optional user-friendly label. */
  label?: string;
}

/**
 * Result of creating a PKCS#11 signer, including the signer and
 * the list of available keys discovered on the token.
 */
export interface Pkcs11SignerResult {
  signer: Signer;
  availableKeys: Pkcs11KeyInfo[];
  /** The PKCS#11 instance (needed for destroyPkcs11Signer). */
  pkcs11Instance: Pkcs11Types.PKCS11;
  /** The PKCS#11 session (needed for destroyPkcs11Signer). */
  session: Pkcs11Session;
}

/**
 * Create a PKCS#11 signer for a hardware token.
 *
 * Opens a session to the token, enumerates keys, selects the target key,
 * extracts the public key (for DID derivation), and returns a Signer
 * that delegates all signing to the hardware token via C_Sign.
 *
 * Supports EC (P-256, P-384) and RSA (2048, 3072, 4096) keys.
 *
 * The session remains open for the lifetime of the signer. Call the
 * returned signer's destroy method (or close the session) when done.
 *
 * @param options - PKCS#11 connection options.
 * @returns Signer instance and list of available keys.
 * @throws {CryptoError} on connection, auth, or key discovery failure.
 */
export function createPkcs11Signer(options: Pkcs11SignerOptions): Pkcs11SignerResult {
  const slotIndex = options.slotIndex ?? 0;

  // Initialize the PKCS#11 library
  const p11 = initializePkcs11(options.libraryPath);

  let session: Pkcs11Session;
  try {
    session = openSession(p11, slotIndex, options.pin);
  } catch (error) {
    finalizePkcs11(p11);
    throw error;
  }

  let availableKeys: Pkcs11KeyInfo[];
  try {
    availableKeys = listKeys(session);
  } catch (error) {
    closeSession(session);
    finalizePkcs11(p11);
    throw error;
  }

  if (availableKeys.length === 0) {
    closeSession(session);
    finalizePkcs11(p11);
    throw new CryptoError("No private keys found on the hardware token");
  }

  // Select the target key
  let targetKey: Pkcs11KeyInfo;
  if (options.keyId) {
    const found = availableKeys.find((k) => k.id === options.keyId);
    if (!found) {
      closeSession(session);
      finalizePkcs11(p11);
      throw new CryptoError(`Key with ID ${options.keyId} not found on token`);
    }
    targetKey = found;
  } else {
    // Use the first available key
    targetKey = availableKeys[0];
  }

  // Build signer based on key type
  let signer: Signer;
  try {
    if (targetKey.keyType === "RSA") {
      signer = buildRsaSigner(session, targetKey, options.label);
    } else {
      signer = buildEcSigner(session, targetKey, options.label);
    }
  } catch (error) {
    closeSession(session);
    finalizePkcs11(p11);
    throw error;
  }

  // Attach certificate chain if available
  try {
    const certs = listCertificates(session);
    const matchingCerts = certs.filter((c) => c.id === targetKey.id);
    if (matchingCerts.length > 0) {
      signer.metadata.certificateChain = matchingCerts.map((c) => derCertToPem(c.derValue));
    }
  } catch {
    // Certificate discovery is optional — don't fail the signer creation
  }

  return { signer, availableKeys, pkcs11Instance: p11, session };
}

/**
 * Build an EC signer (P-256 or P-384) from a PKCS#11 key.
 */
function buildEcSigner(session: Pkcs11Session, targetKey: Pkcs11KeyInfo, label?: string): Signer {
  if (!targetKey.ecPoint) {
    throw new CryptoError(
      "Cannot extract public key from token — the key has no associated public key object",
    );
  }

  const publicKey = publicKeyFromEcPoint(targetKey.ecPoint);
  const id = deriveDidKeyId(publicKey);
  const fingerprint = computeKeyFingerprint(publicKey);

  // Determine algorithm from EC point length
  const algorithm: SigningAlgorithm = targetKey.ecPoint.length === 97 ? "P-384" : "P-256";
  const hashAlgorithm = algorithm === "P-384" ? "sha384" : "sha256";

  // Find the private key handle for signing
  const privateKeyHandle = findPrivateKey(session, targetKey.id);

  const metadata: SignerMetadata = {
    id,
    algorithm,
    type: "pkcs11",
    fingerprint,
    label: label ?? (targetKey.label || undefined),
  };

  return {
    id,
    algorithm,
    type: "pkcs11",
    metadata,

    async sign(data: Uint8Array): Promise<Uint8Array> {
      try {
        // PKCS#11 CKM_ECDSA mechanism expects pre-hashed data.
        const hash = createHash(hashAlgorithm).update(data).digest();

        session.pkcs11.C_SignInit(
          session.handle,
          { mechanism: pkcs11js.CKM_ECDSA },
          privateKeyHandle,
        );
        const rawSignature = session.pkcs11.C_Sign(
          session.handle,
          Buffer.from(hash),
          Buffer.alloc(256),
        );

        return normalizeSignature(new Uint8Array(rawSignature), "EC");
      } catch (error) {
        if (error instanceof CryptoError) throw error;
        throw new CryptoError("PKCS#11 signing operation failed");
      }
    },
  };
}

/**
 * Build an RSA signer from a PKCS#11 key.
 */
function buildRsaSigner(session: Pkcs11Session, targetKey: Pkcs11KeyInfo, label?: string): Signer {
  if (!targetKey.rsaModulus || !targetKey.rsaPublicExponent) {
    throw new CryptoError("Cannot extract RSA public key from token — missing modulus or exponent");
  }

  const publicKey = publicKeyFromRsaComponents(targetKey.rsaModulus, targetKey.rsaPublicExponent);
  const jwk = publicKey.export({ format: "jwk" }) as { kty: string; [key: string]: unknown };
  const did = encodeDidJwk(jwk);
  const id = didJwkVerificationMethodId(did);
  const fingerprint = computeKeyFingerprint(publicKey);

  // Determine RSA algorithm from modulus bit length
  const modulusBitLength = targetKey.rsaModulus.length * 8;
  const algorithm = rsaAlgorithmFromModulusBits(modulusBitLength);

  // Find the private key handle for signing
  const privateKeyHandle = findPrivateKey(session, targetKey.id);

  const metadata: SignerMetadata = {
    id,
    algorithm,
    type: "pkcs11",
    fingerprint,
    label: label ?? (targetKey.label || undefined),
  };

  return {
    id,
    algorithm,
    type: "pkcs11",
    metadata,

    async sign(data: Uint8Array): Promise<Uint8Array> {
      try {
        // RSA-PSS with SHA-256 hash, MGF1-SHA256, salt length = 32
        const rsaPssParams: Pkcs11Types.RsaPSS = {
          type: pkcs11js.CK_PARAMS_RSA_PSS,
          hashAlg: pkcs11js.CKM_SHA256,
          mgf: pkcs11js.CKG_MGF1_SHA256,
          saltLen: 32,
        };
        session.pkcs11.C_SignInit(
          session.handle,
          { mechanism: pkcs11js.CKM_RSA_PKCS_PSS, parameter: rsaPssParams },
          privateKeyHandle,
        );

        const hash = createHash("sha256").update(data).digest();
        const rawSignature = session.pkcs11.C_Sign(
          session.handle,
          Buffer.from(hash),
          Buffer.alloc(512),
        );

        return normalizeSignature(new Uint8Array(rawSignature), "RSA");
      } catch (error) {
        if (error instanceof CryptoError) throw error;
        throw new CryptoError("PKCS#11 RSA signing operation failed");
      }
    },
  };
}

/**
 * Destroy a PKCS#11 signer's session and free resources.
 *
 * This should be called when the signer is no longer needed. After calling
 * this, any further sign() calls will fail.
 *
 * @param session - The PKCS#11 session to close.
 * @param pkcs11 - The PKCS11 instance to finalize.
 */
export function destroyPkcs11Signer(
  session: Pkcs11Session,
  pkcs11Instance: Pkcs11Types.PKCS11,
): void {
  closeSession(session);
  finalizePkcs11(pkcs11Instance);
}
