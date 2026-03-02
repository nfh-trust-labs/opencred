/**
 * PKCS#11 signer for the OpenCred desktop app.
 *
 * Implements the Signer interface using a hardware token via PKCS#11.
 * The private key NEVER leaves the hardware token — all signing operations
 * are performed on-device via C_Sign. Only the public key is extracted
 * for did:key derivation and metadata.
 *
 * SECURITY INVARIANTS:
 *  - The private key stays on the hardware token at all times.
 *  - The PIN is used for session login only and is never stored.
 *  - No key material is logged. Only the key fingerprint and did:key ID
 *    appear in metadata.
 *  - Sessions are always closed in a finally block.
 *  - Signature format: CKM_ECDSA returns raw r||s (64 bytes for P-256).
 *    Some tokens may return DER — normalizeSignature handles conversion.
 */

import * as pkcs11js from "pkcs11js";
import { createHash } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import type { Signer, SignerMetadata } from "./types.js";
import {
  initializePkcs11,
  finalizePkcs11,
  openSession,
  closeSession,
  listKeys,
  findPrivateKey,
  type Pkcs11Session,
  type Pkcs11KeyInfo,
} from "./pkcs11-session.js";
import {
  publicKeyFromEcPoint,
  deriveDidKeyIdFromPublicKey,
  computeFingerprint,
  normalizeSignature,
} from "./pkcs11-utils.js";

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
  /** Hex-encoded CKA_ID of the key to use. If not provided, uses first EC key. */
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
  pkcs11Instance: pkcs11js.PKCS11;
  /** The PKCS#11 session (needed for destroyPkcs11Signer). */
  session: Pkcs11Session;
}

/**
 * Create a PKCS#11 signer for a hardware token.
 *
 * Opens a session to the token, enumerates keys, selects the target key,
 * extracts the public key (for did:key derivation), and returns a Signer
 * that delegates all signing to the hardware token via C_Sign.
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
    throw new CryptoError("No EC private keys found on the hardware token");
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
    // Use the first available EC key
    targetKey = availableKeys[0];
  }

  if (!targetKey.ecPoint) {
    closeSession(session);
    finalizePkcs11(p11);
    throw new CryptoError(
      "Cannot extract public key from token — the key has no associated public key object",
    );
  }

  // Derive did:key and fingerprint from the public key
  let id: string;
  let fingerprint: string;
  try {
    const publicKey = publicKeyFromEcPoint(targetKey.ecPoint);
    id = deriveDidKeyIdFromPublicKey(publicKey);
    fingerprint = computeFingerprint(publicKey);
  } catch (error) {
    closeSession(session);
    finalizePkcs11(p11);
    throw error;
  }

  // Find the private key handle for signing
  let privateKeyHandle: Buffer;
  try {
    privateKeyHandle = findPrivateKey(session, targetKey.id);
  } catch (error) {
    closeSession(session);
    finalizePkcs11(p11);
    throw error;
  }

  const metadata: SignerMetadata = {
    id,
    algorithm: "P-256",
    type: "pkcs11",
    fingerprint,
    label: options.label ?? (targetKey.label || undefined),
  };

  const signer: Signer = {
    id,
    algorithm: "P-256",
    type: "pkcs11",
    metadata,

    async sign(data: Uint8Array): Promise<Uint8Array> {
      try {
        // PKCS#11 CKM_ECDSA mechanism expects pre-hashed data.
        // The caller provides the concatenated hash pair (proofConfigHash || documentHash,
        // 64 bytes). The signing flow in software-signer uses createSign("SHA256") which
        // applies SHA-256 before ECDSA. For PKCS#11 CKM_ECDSA, we must hash first.
        const hash = createHash("sha256").update(data).digest();

        // Sign using the hardware token
        session.pkcs11.C_SignInit(
          session.handle,
          { mechanism: pkcs11js.CKM_ECDSA },
          privateKeyHandle,
        );
        const rawSignature = session.pkcs11.C_Sign(
          session.handle,
          Buffer.from(hash),
          Buffer.alloc(128),
        );

        // Normalize the signature to raw r||s (64 bytes)
        return normalizeSignature(new Uint8Array(rawSignature));
      } catch (error) {
        if (error instanceof CryptoError) throw error;
        throw new CryptoError("PKCS#11 signing operation failed");
      }
    },
  };

  return { signer, availableKeys, pkcs11Instance: p11, session };
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
export function destroyPkcs11Signer(session: Pkcs11Session, pkcs11Instance: pkcs11js.PKCS11): void {
  closeSession(session);
  finalizePkcs11(pkcs11Instance);
}
