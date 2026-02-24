/**
 * PKCS#11 session lifecycle manager.
 *
 * Wraps the pkcs11js library to manage sessions with hardware tokens.
 * Handles library initialization, slot enumeration, session open/close,
 * PIN authentication, and key enumeration.
 *
 * SECURITY INVARIANTS:
 *  - Private keys NEVER leave the token. Only metadata (label, ID, type)
 *    is returned from key enumeration.
 *  - The PIN is used for login only and is never stored or logged.
 *  - Sessions are always closed in a finally block, even on error.
 *  - No key material is logged — only key labels and fingerprints.
 */

import * as pkcs11js from "pkcs11js";
import { CryptoError } from "@opencred/shared";

/**
 * CKF_TOKEN_PRESENT is 0x01 per the PKCS#11 spec but is not exported
 * from the pkcs11js type definitions. Define it as a local constant.
 */
const CKF_TOKEN_PRESENT = 0x00000001;

/**
 * Metadata about a key on a PKCS#11 token — safe to transmit over IPC.
 * NEVER contains the actual private key.
 */
export interface Pkcs11KeyInfo {
  /** The CKA_LABEL of the key. */
  label: string;
  /** The CKA_ID of the key (hex-encoded). */
  id: string;
  /** The key type (e.g., "EC"). */
  keyType: string;
  /** Whether this key has a matching public key on the token. */
  hasPublicKey: boolean;
  /** The EC point bytes of the associated public key (uncompressed, if available). */
  ecPoint?: Uint8Array;
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
  pkcs11: pkcs11js.PKCS11;
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
export function initializePkcs11(libraryPath: string): pkcs11js.PKCS11 {
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
export function finalizePkcs11(pkcs11: pkcs11js.PKCS11): void {
  try {
    pkcs11.C_Finalize();
  } catch {
    // Ignore finalize errors during cleanup
  }
}

/**
 * List available PKCS#11 slots.
 *
 * @param pkcs11 - An initialized PKCS11 instance.
 * @returns Array of slot information.
 */
export function listSlots(pkcs11: pkcs11js.PKCS11): Pkcs11SlotInfo[] {
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
        } catch {
          // Token info unavailable — still report the slot
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
  pkcs11: pkcs11js.PKCS11,
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
    } catch {
      // Ignore close errors during error handling
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
          ? Buffer.from(attrs[0].value as Buffer).toString("utf-8").trim()
          : "";
        const id = attrs[1].value
          ? Buffer.from(attrs[1].value as Buffer).toString("hex")
          : "";
        const keyTypeVal = attrs[2].value
          ? (attrs[2].value as Buffer).readUInt32LE(0)
          : 0;

        // Map PKCS#11 key type to string
        const keyType = keyTypeVal === pkcs11js.CKK_EC ? "EC" : `unknown(${keyTypeVal})`;

        // Only include EC keys (we only support P-256)
        if (keyTypeVal === pkcs11js.CKK_EC) {
          // Try to find the matching public key to get the EC point
          let ecPoint: Uint8Array | undefined;
          let hasPublicKey = false;

          try {
            ecPoint = findPublicKeyPoint(session, attrs[1].value as Buffer);
            hasPublicKey = ecPoint !== undefined;
          } catch {
            // Public key lookup failed — still report the key
          }

          keys.push({
            label,
            id,
            keyType,
            hasPublicKey,
            ecPoint,
          });
        }
      } catch {
        // Skip keys we can't read
      }

      obj = pkcs11.C_FindObjects(handle);
    }

    pkcs11.C_FindObjectsFinal(handle);
  } catch (error) {
    try {
      pkcs11.C_FindObjectsFinal(handle);
    } catch {
      // Ignore
    }
    throw new CryptoError(
      `Failed to enumerate keys: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }

  return keys;
}

/**
 * Find the EC public key point matching a given CKA_ID.
 *
 * @param session - An open PKCS#11 session.
 * @param keyId - The CKA_ID to search for.
 * @returns The EC point bytes (uncompressed), or undefined if not found.
 */
function findPublicKeyPoint(
  session: Pkcs11Session,
  keyId: Buffer,
): Uint8Array | undefined {
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
      { type: pkcs11js.CKA_EC_POINT },
    ]);

    if (!attrs[0].value) {
      return undefined;
    }

    const raw = Buffer.from(attrs[0].value as Buffer);

    // The EC_POINT may be DER-encoded (OCTET STRING wrapping the point)
    // or raw uncompressed point. Check for DER wrapper.
    if (raw[0] === 0x04 && raw.length === 65) {
      // Raw uncompressed point
      return new Uint8Array(raw);
    }

    // DER OCTET STRING: tag(0x04) length(65) point(65 bytes)
    if (raw.length > 2 && raw[0] === 0x04 && raw[1] === 65 && raw.length === 67) {
      return new Uint8Array(raw.subarray(2));
    }

    // Fallback: try to use what we have
    if (raw.length >= 65) {
      // Might have extra wrapper bytes — try to find the 0x04 point prefix
      for (let i = 0; i <= raw.length - 65; i++) {
        if (raw[i] === 0x04) {
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
    } catch {
      // Ignore
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
      } catch {
        // Ignore logout errors
      }
      session.loggedIn = false;
    }
    session.pkcs11.C_CloseSession(session.handle);
  } catch {
    // Session may already be closed — ignore
  }
}
