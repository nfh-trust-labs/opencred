/**
 * PKCS#11 session lifecycle manager.
 *
 * Wraps the pkcs11js library to manage sessions with hardware tokens.
 * Handles library initialization, slot enumeration, session open/close,
 * PIN authentication, key enumeration, and certificate discovery.
 *
 * SECURITY INVARIANTS:
 *  - Private keys NEVER leave the token. Only metadata (label, ID, type)
 *    is returned from key enumeration.
 *  - The PIN is used for login only and is never stored or logged.
 *  - Sessions are always closed in a finally block, even on error.
 *  - No key material is logged — only key labels and fingerprints.
 */

import { CryptoError } from "@opencred/shared";
import type * as Pkcs11Types from "pkcs11js";
import { loadPkcs11js } from "./pkcs11-loader.js";

/**
 * Minimal logger interface for PKCS#11 diagnostics. Compatible with a
 * Pino logger instance (both accept `(msg, meta?)`) and intentionally
 * narrower — this module doesn't need info/debug/trace levels. See
 * Anand's P2-09.
 */
export interface Pkcs11Logger {
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
}

const noopLogger: Pkcs11Logger = {
  warn: () => undefined,
  error: () => undefined,
};

/**
 * Process-wide logger for PKCS#11 warnings. The desktop main process
 * installs its structured Pino logger at startup via `setPkcs11Logger`.
 * Other consumers (tests, CLI, non-Electron runtimes) get a noop by
 * default, which is strictly better than the previous `console.warn`:
 * warnings stop leaking into stderr-shaped output that nobody can
 * filter, and production deployments can opt in through the operator
 * logger without changing call sites.
 */
let logger: Pkcs11Logger = noopLogger;

/** Install the process-wide PKCS#11 logger. Intended for bootstrap only. */
export function setPkcs11Logger(pinoCompatible: Pkcs11Logger): void {
  logger = pinoCompatible;
}

/** Clear the logger — intended for tests. */
export function resetPkcs11Logger(): void {
  logger = noopLogger;
}

function errMeta(error: unknown): Record<string, unknown> {
  return {
    error: error instanceof Error ? error.message : String(error),
  };
}

/**
 * Lazy accessor for the pkcs11js module.
 *
 * Uses a Proxy so that any property access (constants, classes, etc.)
 * triggers loading of the native addon on first use. This means importing
 * pkcs11-session.ts never crashes — the native addon is only loaded when
 * a PKCS#11 function is actually called.
 *
 * See pkcs11-loader.ts for the full rationale.
 */
const pkcs11js: typeof Pkcs11Types = new Proxy({} as typeof Pkcs11Types, {
  get(_target, prop: string) {
    return (loadPkcs11js() as Record<string, unknown>)[prop];
  },
});

/**
 * CKF_TOKEN_PRESENT is 0x01 per the PKCS#11 spec but is not exported
 * from the pkcs11js type definitions. Define it as a local constant.
 */
const CKF_TOKEN_PRESENT = 0x00000001;

/** PKCS#11 key type constant for RSA keys. */
const CKK_RSA = 0x00000000;

/** PKCS#11 attribute: RSA modulus. */
const CKA_MODULUS = 0x00000120;

/** PKCS#11 attribute: RSA public exponent. */
const CKA_PUBLIC_EXPONENT = 0x00000122;

/** PKCS#11 object class: certificate. */
const CKO_CERTIFICATE = 0x00000001;

/** PKCS#11 attribute: object value (for certificates). */
const CKA_VALUE = 0x00000011;

/**
 * Metadata about a key on a PKCS#11 token — safe to transmit over IPC.
 * NEVER contains the actual private key.
 */
export interface Pkcs11KeyInfo {
  /** The CKA_LABEL of the key. */
  label: string;
  /** The CKA_ID of the key (hex-encoded). */
  id: string;
  /** The key type. */
  keyType: "EC" | "RSA";
  /** Whether this key has a matching public key on the token. */
  hasPublicKey: boolean;
  /** The EC point bytes of the associated public key (uncompressed, if available). */
  ecPoint?: Uint8Array;
  /** The RSA modulus bytes (if RSA key). */
  rsaModulus?: Uint8Array;
  /** The RSA public exponent bytes (if RSA key). */
  rsaPublicExponent?: Uint8Array;
}

/**
 * Metadata about an X.509 certificate on a PKCS#11 token.
 */
export interface Pkcs11CertInfo {
  /** The CKA_LABEL of the certificate. */
  label: string;
  /** The CKA_ID — matches the key's CKA_ID (hex-encoded). */
  id: string;
  /** The DER-encoded X.509 certificate (CKA_VALUE). */
  derValue: Uint8Array;
}

/**
 * Metadata about a PKCS#11 slot/token.
 */
export interface Pkcs11SlotInfo {
  /** Slot index. */
  index: number;
  /** Slot description. */
  description: string;
  /** Whether a token is present in this slot. */
  tokenPresent: boolean;
  /** Token label (if present). */
  tokenLabel?: string;
  /** Token manufacturer. */
  tokenManufacturer?: string;
}

/**
 * A managed PKCS#11 session handle.
 */
export interface Pkcs11Session {
  /** The pkcs11js PKCS11 instance. */
  pkcs11: Pkcs11Types.PKCS11;
  /** The session handle. */
  handle: Buffer;
  /** The slot index. */
  slotIndex: number;
  /** Whether the session is logged in. */
  loggedIn: boolean;
}

/**
 * Initialize a PKCS#11 library and return the PKCS11 instance.
 *
 * @param libraryPath - Absolute path to the PKCS#11 shared library (.so/.dll/.dylib).
 * @returns Initialized PKCS11 instance.
 * @throws {CryptoError} if the library cannot be loaded.
 */
export function initializePkcs11(libraryPath: string): Pkcs11Types.PKCS11 {
  try {
    const p11 = new pkcs11js.PKCS11();
    p11.load(libraryPath);
    p11.C_Initialize();
    return p11;
  } catch (error) {
    throw new CryptoError(
      `Failed to initialize PKCS#11 library: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Finalize and clean up a PKCS#11 library instance.
 *
 * @param pkcs11 - The PKCS11 instance to finalize.
 */
export function finalizePkcs11(pkcs11: Pkcs11Types.PKCS11): void {
  try {
    pkcs11.C_Finalize();
  } catch (error) {
    logger.warn("[PKCS#11] C_Finalize failed during cleanup", errMeta(error));
  }
}

/**
 * List available PKCS#11 slots.
 *
 * @param pkcs11 - An initialized PKCS11 instance.
 * @returns Array of slot information.
 */
export function listSlots(pkcs11: Pkcs11Types.PKCS11): Pkcs11SlotInfo[] {
  try {
    // Get all slots (including those without tokens)
    const slots = pkcs11.C_GetSlotList(false);
    const result: Pkcs11SlotInfo[] = [];

    for (let i = 0; i < slots.length; i++) {
      const slotInfo = pkcs11.C_GetSlotInfo(slots[i]);
      const tokenPresent = (slotInfo.flags & CKF_TOKEN_PRESENT) !== 0;

      const info: Pkcs11SlotInfo = {
        index: i,
        description: slotInfo.slotDescription.trim(),
        tokenPresent,
      };

      if (tokenPresent) {
        try {
          const tokenInfo = pkcs11.C_GetTokenInfo(slots[i]);
          info.tokenLabel = tokenInfo.label.trim();
          info.tokenManufacturer = tokenInfo.manufacturerID.trim();
        } catch (error) {
          logger.warn("[PKCS#11] Failed to read token info for slot", {
            slot: i,
            ...errMeta(error),
          });
        }
      }

      result.push(info);
    }

    return result;
  } catch (error) {
    throw new CryptoError(
      `Failed to enumerate PKCS#11 slots: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Open a PKCS#11 session and log in with the provided PIN.
 *
 * @param pkcs11 - An initialized PKCS11 instance.
 * @param slotIndex - The slot index to open.
 * @param pin - The user PIN for the token (never stored or logged).
 * @returns A managed session handle.
 * @throws {CryptoError} if the session cannot be opened or PIN is wrong.
 */
export function openSession(
  pkcs11: Pkcs11Types.PKCS11,
  slotIndex: number,
  pin: string,
): Pkcs11Session {
  const slots = pkcs11.C_GetSlotList(true); // only slots with tokens
  if (slotIndex >= slots.length) {
    throw new CryptoError(
      `Slot index ${slotIndex} is out of range. Available slots: ${slots.length}`,
    );
  }

  let handle: Buffer;
  try {
    handle = pkcs11.C_OpenSession(
      slots[slotIndex],
      pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION,
    );
  } catch (error) {
    throw new CryptoError(
      `Failed to open PKCS#11 session: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }

  try {
    pkcs11.C_Login(handle, pkcs11js.CKU_USER, pin);
  } catch (error) {
    // Close the session if login fails
    try {
      pkcs11.C_CloseSession(handle);
    } catch (closeError) {
      logger.warn("[PKCS#11] Failed to close session after login failure", errMeta(closeError));
    }
    throw new CryptoError(
      `PKCS#11 login failed (wrong PIN or token error): ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }

  return {
    pkcs11,
    handle,
    slotIndex,
    loggedIn: true,
  };
}

/**
 * List private keys on the token.
 *
 * Returns metadata only — the private key material NEVER leaves the token.
 * Supports both EC (P-256, P-384) and RSA keys.
 *
 * @param session - An open and logged-in PKCS#11 session.
 * @returns Array of key metadata.
 */
export function listKeys(session: Pkcs11Session): Pkcs11KeyInfo[] {
  const { pkcs11, handle } = session;
  const keys: Pkcs11KeyInfo[] = [];

  try {
    // Find private key objects
    pkcs11.C_FindObjectsInit(handle, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
    ]);

    let obj = pkcs11.C_FindObjects(handle);
    while (obj) {
      try {
        const attrs = pkcs11.C_GetAttributeValue(handle, obj, [
          { type: pkcs11js.CKA_LABEL },
          { type: pkcs11js.CKA_ID },
          { type: pkcs11js.CKA_KEY_TYPE },
        ]);

        const label = attrs[0].value
          ? Buffer.from(attrs[0].value as Buffer)
              .toString("utf-8")
              .trim()
          : "";
        const id = attrs[1].value ? Buffer.from(attrs[1].value as Buffer).toString("hex") : "";
        const keyTypeVal = attrs[2].value ? (attrs[2].value as Buffer).readUInt32LE(0) : -1;

        if (keyTypeVal === pkcs11js.CKK_EC) {
          // EC key — try to find the matching public key to get the EC point
          let ecPoint: Uint8Array | undefined;
          let hasPublicKey = false;

          try {
            ecPoint = findPublicKeyEcPoint(session, attrs[1].value as Buffer);
            hasPublicKey = ecPoint !== undefined;
          } catch {
            // Public key lookup failed — still report the key
          }

          keys.push({
            label,
            id,
            keyType: "EC",
            hasPublicKey,
            ecPoint,
          });
        } else if (keyTypeVal === CKK_RSA) {
          // RSA key — read modulus and public exponent from the public key object
          let rsaModulus: Uint8Array | undefined;
          let rsaPublicExponent: Uint8Array | undefined;
          let hasPublicKey = false;

          try {
            const rsaComponents = findPublicKeyRsaComponents(session, attrs[1].value as Buffer);
            if (rsaComponents) {
              rsaModulus = rsaComponents.modulus;
              rsaPublicExponent = rsaComponents.publicExponent;
              hasPublicKey = true;
            }
          } catch {
            // Public key lookup failed — still report the key
          }

          keys.push({
            label,
            id,
            keyType: "RSA",
            hasPublicKey,
            rsaModulus,
            rsaPublicExponent,
          });
        }
        // Unknown key types are silently skipped
      } catch (error) {
        logger.warn("[PKCS#11] Skipping unreadable key during enumeration", errMeta(error));
      }

      obj = pkcs11.C_FindObjects(handle);
    }

    pkcs11.C_FindObjectsFinal(handle);
  } catch (error) {
    try {
      pkcs11.C_FindObjectsFinal(handle);
    } catch (finalizeError) {
      logger.warn(
        "[PKCS#11] C_FindObjectsFinal failed during key enumeration cleanup",
        errMeta(finalizeError),
      );
    }
    throw new CryptoError(
      `Failed to enumerate keys: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }

  return keys;
}

/**
 * List X.509 certificates on the token.
 *
 * @param session - An open and logged-in PKCS#11 session.
 * @returns Array of certificate metadata.
 */
export function listCertificates(session: Pkcs11Session): Pkcs11CertInfo[] {
  const { pkcs11, handle } = session;
  const certs: Pkcs11CertInfo[] = [];

  try {
    pkcs11.C_FindObjectsInit(handle, [{ type: pkcs11js.CKA_CLASS, value: CKO_CERTIFICATE }]);

    let obj = pkcs11.C_FindObjects(handle);
    while (obj) {
      try {
        const attrs = pkcs11.C_GetAttributeValue(handle, obj, [
          { type: pkcs11js.CKA_LABEL },
          { type: pkcs11js.CKA_ID },
          { type: CKA_VALUE },
        ]);

        const label = attrs[0].value
          ? Buffer.from(attrs[0].value as Buffer)
              .toString("utf-8")
              .trim()
          : "";
        const id = attrs[1].value ? Buffer.from(attrs[1].value as Buffer).toString("hex") : "";
        const derValue = attrs[2].value
          ? new Uint8Array(Buffer.from(attrs[2].value as Buffer))
          : undefined;

        if (derValue) {
          certs.push({ label, id, derValue });
        }
      } catch (error) {
        logger.warn("[PKCS#11] Skipping unreadable certificate during enumeration", errMeta(error));
      }

      obj = pkcs11.C_FindObjects(handle);
    }

    pkcs11.C_FindObjectsFinal(handle);
  } catch (error) {
    try {
      pkcs11.C_FindObjectsFinal(handle);
    } catch (finalizeError) {
      logger.warn(
        "[PKCS#11] C_FindObjectsFinal failed during certificate enumeration cleanup",
        errMeta(finalizeError),
      );
    }
    throw new CryptoError(
      `Failed to enumerate certificates: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }

  return certs;
}

/**
 * Find the EC public key point matching a given CKA_ID.
 *
 * Supports both P-256 (65-byte) and P-384 (97-byte) uncompressed points.
 *
 * @param session - An open PKCS#11 session.
 * @param keyId - The CKA_ID to search for.
 * @returns The EC point bytes (uncompressed), or undefined if not found.
 */
function findPublicKeyEcPoint(session: Pkcs11Session, keyId: Buffer): Uint8Array | undefined {
  const { pkcs11, handle } = session;

  try {
    pkcs11.C_FindObjectsInit(handle, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_ID, value: keyId },
    ]);

    const obj = pkcs11.C_FindObjects(handle);
    pkcs11.C_FindObjectsFinal(handle);

    if (!obj) {
      return undefined;
    }

    const attrs = pkcs11.C_GetAttributeValue(handle, obj, [{ type: pkcs11js.CKA_EC_POINT }]);

    if (!attrs[0].value) {
      return undefined;
    }

    const raw = Buffer.from(attrs[0].value as Buffer);

    // P-256: raw uncompressed point (65 bytes starting with 0x04)
    if (raw[0] === 0x04 && raw.length === 65) {
      return new Uint8Array(raw);
    }

    // P-384: raw uncompressed point (97 bytes starting with 0x04)
    if (raw[0] === 0x04 && raw.length === 97) {
      return new Uint8Array(raw);
    }

    // DER OCTET STRING wrapping P-256: tag(0x04) length(65) point(65 bytes) = 67 bytes
    if (raw.length > 2 && raw[0] === 0x04 && raw[1] === 65 && raw.length === 67) {
      return new Uint8Array(raw.subarray(2));
    }

    // DER OCTET STRING wrapping P-384: tag(0x04) length(97) point(97 bytes) = 99 bytes
    if (raw.length > 2 && raw[0] === 0x04 && raw[1] === 97 && raw.length === 99) {
      return new Uint8Array(raw.subarray(2));
    }

    // Fallback: try to find the 0x04 point prefix for P-256
    if (raw.length >= 65) {
      for (let i = 0; i <= raw.length - 65; i++) {
        if (raw[i] === 0x04) {
          // Check if it could be P-384 first (97 bytes from this offset)
          if (i <= raw.length - 97) {
            return new Uint8Array(raw.subarray(i, i + 97));
          }
          return new Uint8Array(raw.subarray(i, i + 65));
        }
      }
    }

    return new Uint8Array(raw);
  } catch {
    return undefined;
  }
}

/**
 * Find the RSA public key components (modulus and exponent) matching a given CKA_ID.
 *
 * @param session - An open PKCS#11 session.
 * @param keyId - The CKA_ID to search for.
 * @returns The RSA modulus and public exponent, or undefined if not found.
 */
function findPublicKeyRsaComponents(
  session: Pkcs11Session,
  keyId: Buffer,
): { modulus: Uint8Array; publicExponent: Uint8Array } | undefined {
  const { pkcs11, handle } = session;

  try {
    pkcs11.C_FindObjectsInit(handle, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_ID, value: keyId },
    ]);

    const obj = pkcs11.C_FindObjects(handle);
    pkcs11.C_FindObjectsFinal(handle);

    if (!obj) {
      return undefined;
    }

    const attrs = pkcs11.C_GetAttributeValue(handle, obj, [
      { type: CKA_MODULUS },
      { type: CKA_PUBLIC_EXPONENT },
    ]);

    const modulus = attrs[0].value
      ? new Uint8Array(Buffer.from(attrs[0].value as Buffer))
      : undefined;
    const publicExponent = attrs[1].value
      ? new Uint8Array(Buffer.from(attrs[1].value as Buffer))
      : undefined;

    if (!modulus || !publicExponent) {
      return undefined;
    }

    return { modulus, publicExponent };
  } catch {
    return undefined;
  }
}

/**
 * Find a private key handle by CKA_ID (hex-encoded).
 *
 * @param session - An open PKCS#11 session.
 * @param keyIdHex - The hex-encoded CKA_ID of the key.
 * @returns The PKCS#11 object handle for the private key.
 * @throws {CryptoError} if the key is not found.
 */
export function findPrivateKey(session: Pkcs11Session, keyIdHex: string): Buffer {
  const { pkcs11, handle } = session;
  const keyId = Buffer.from(keyIdHex, "hex");

  try {
    pkcs11.C_FindObjectsInit(handle, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_ID, value: keyId },
    ]);

    const obj = pkcs11.C_FindObjects(handle);
    pkcs11.C_FindObjectsFinal(handle);

    if (!obj) {
      throw new CryptoError(`Private key not found on token for ID: ${keyIdHex}`);
    }

    return obj;
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    try {
      pkcs11.C_FindObjectsFinal(handle);
    } catch (finalizeError) {
      logger.warn(
        "[PKCS#11] C_FindObjectsFinal failed during private key lookup cleanup",
        errMeta(finalizeError),
      );
    }
    throw new CryptoError(
      `Failed to find private key: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Close a PKCS#11 session. Always safe to call, even if already closed.
 *
 * @param session - The session to close.
 */
export function closeSession(session: Pkcs11Session): void {
  try {
    if (session.loggedIn) {
      try {
        session.pkcs11.C_Logout(session.handle);
      } catch (error) {
        logger.warn("[PKCS#11] C_Logout failed during session close", errMeta(error));
      }
      session.loggedIn = false;
    }
    session.pkcs11.C_CloseSession(session.handle);
  } catch (error) {
    logger.warn("[PKCS#11] C_CloseSession failed (session may already be closed)", errMeta(error));
  }
}

// NOTE: p11-kit auto-discovery is in p11-kit-discovery.ts (separate module
// to avoid pulling in the pkcs11js native dependency for non-PKCS#11 callers).
