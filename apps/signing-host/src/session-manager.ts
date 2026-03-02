/**
 * Session manager for the native messaging host.
 *
 * Manages active PKCS#11 sessions and OS cert signers. Each connected
 * signer is tracked by a generated signerId (UUID) so the browser
 * extension can reference it across multiple requests.
 *
 * SECURITY INVARIANTS:
 *  - PINs are used for session login only and are immediately discarded.
 *  - No key material is stored, logged, or included in error messages.
 *  - Only signer metadata (fingerprint, did:key ID) crosses the boundary.
 *  - Sessions are cleaned up on disconnect.
 */

import { randomUUID } from "node:crypto";
import {
  createPkcs11Signer,
  destroyPkcs11Signer,
  initializePkcs11,
  finalizePkcs11,
  listSlots,
  openSession,
  closeSession,
  listKeys,
  listOsCertificates,
  createOsCertSigner,
  type Signer,
  type SignerMetadata,
  type Pkcs11Session,
  type Pkcs11SlotInfo,
  type Pkcs11KeyInfo,
  type OsCertListResult,
} from "@opencred/signing";
import * as pkcs11js from "pkcs11js";

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

interface Pkcs11ManagedSession {
  kind: "pkcs11";
  signer: Signer;
  pkcs11Instance: pkcs11js.PKCS11;
  session: Pkcs11Session;
}

interface OsCertManagedSession {
  kind: "os-cert";
  signer: Signer;
}

type ManagedSession = Pkcs11ManagedSession | OsCertManagedSession;

/** Active sessions keyed by signerId. */
const sessions = new Map<string, ManagedSession>();

// ---------------------------------------------------------------------------
// PKCS#11 operations
// ---------------------------------------------------------------------------

/**
 * Detect whether PKCS#11 is available on this system.
 *
 * Tries to instantiate pkcs11js. If the native module loads, PKCS#11
 * support is available.
 *
 * @returns Whether pkcs11js can be loaded.
 */
export function pkcs11Detect(): { available: boolean } {
  try {
    // If pkcs11js imported successfully (at module level), it's available
    new pkcs11js.PKCS11();
    return { available: true };
  } catch {
    return { available: false };
  }
}

/**
 * List PKCS#11 slots for a given library.
 *
 * Opens the library, enumerates slots, then cleans up.
 *
 * @param libraryPath - Absolute path to the PKCS#11 shared library.
 * @returns Array of slot information.
 */
export function pkcs11ListSlots(libraryPath: string): Pkcs11SlotInfo[] {
  const p11 = initializePkcs11(libraryPath);
  try {
    return listSlots(p11);
  } finally {
    finalizePkcs11(p11);
  }
}

/**
 * List keys on a PKCS#11 token.
 *
 * Opens the library, opens a session with PIN, enumerates keys,
 * then cleans up. The PIN is used only for C_Login and is not stored.
 *
 * @param libraryPath - Absolute path to the PKCS#11 shared library.
 * @param slotIndex - The slot index.
 * @param pin - The user PIN (used for login, then discarded).
 * @returns Array of key metadata (no private key material).
 */
export function pkcs11ListKeys(
  libraryPath: string,
  slotIndex: number,
  pin: string,
): Pkcs11KeyInfo[] {
  const p11 = initializePkcs11(libraryPath);
  let session: Pkcs11Session | null = null;
  try {
    session = openSession(p11, slotIndex, pin);
    return listKeys(session);
  } finally {
    if (session) closeSession(session);
    finalizePkcs11(p11);
  }
}

/**
 * Connect to a PKCS#11 token and create a signer.
 *
 * Opens a persistent session and creates a signer that can be used
 * for subsequent signing requests. The session remains open until
 * pkcs11Disconnect is called.
 *
 * @param libraryPath - Absolute path to the PKCS#11 shared library.
 * @param slotIndex - The slot index.
 * @param pin - The user PIN (used for login, then discarded).
 * @param keyId - Optional hex CKA_ID of the key to use.
 * @param label - Optional user-friendly label.
 * @returns The signerId and signer metadata.
 */
export function pkcs11Connect(
  libraryPath: string,
  slotIndex: number,
  pin: string,
  keyId?: string,
  label?: string,
): { signerId: string; metadata: SignerMetadata } {
  const { signer, pkcs11Instance, session } = createPkcs11Signer({
    libraryPath,
    slotIndex,
    pin,
    keyId,
    label,
  });

  const signerId = randomUUID();

  sessions.set(signerId, {
    kind: "pkcs11",
    signer,
    pkcs11Instance,
    session,
  });

  return {
    signerId,
    metadata: signer.metadata,
  };
}

/**
 * Sign data using an active PKCS#11 signer.
 *
 * @param signerId - The signer ID from pkcs11Connect.
 * @param data - The data to sign (raw bytes).
 * @returns The raw r||s signature (64 bytes for P-256).
 * @throws Error if the signerId is not found.
 */
export async function pkcs11Sign(
  signerId: string,
  data: Uint8Array,
): Promise<Uint8Array> {
  const managed = sessions.get(signerId);
  if (!managed) {
    throw new Error("Signer not found — session may have been disconnected");
  }

  return managed.signer.sign(data);
}

/**
 * Disconnect a PKCS#11 signer and clean up its session.
 *
 * @param signerId - The signer ID from pkcs11Connect.
 */
export function pkcs11Disconnect(signerId: string): void {
  const managed = sessions.get(signerId);
  if (!managed || managed.kind !== "pkcs11") {
    sessions.delete(signerId);
    return;
  }

  try {
    destroyPkcs11Signer(managed.session, managed.pkcs11Instance);
  } catch {
    // Ignore cleanup errors
  }

  sessions.delete(signerId);
}

// ---------------------------------------------------------------------------
// OS cert operations
// ---------------------------------------------------------------------------

/**
 * List certificates from the OS certificate store.
 *
 * Delegates to @opencred/signing's listOsCertificates. No PIN is needed —
 * the OS handles authentication (macOS Keychain prompt, Windows UAC).
 *
 * @param platform - Override the detected platform (for testing).
 * @returns Certificate list with platform metadata.
 */
export async function oscertList(
  platform?: "darwin" | "win32" | "linux",
): Promise<OsCertListResult> {
  const p = platform ?? (process.platform as "darwin" | "win32" | "linux");
  return listOsCertificates(p);
}

/**
 * Connect to an OS certificate and create a signer.
 *
 * The signer delegates all signing to the OS cryptography subsystem.
 * The private key never leaves the OS.
 *
 * @param certificateId - Platform-specific certificate identifier.
 * @param platform - Override the detected platform (for testing).
 * @param label - Optional user-friendly label.
 * @returns The signerId and signer metadata.
 */
export async function oscertConnect(
  certificateId: string,
  platform?: "darwin" | "win32" | "linux",
  label?: string,
): Promise<{ signerId: string; metadata: SignerMetadata }> {
  const p = platform ?? (process.platform as "darwin" | "win32" | "linux");

  const { signer } = await createOsCertSigner({
    platform: p,
    certificateId,
    label,
  });

  const signerId = randomUUID();

  sessions.set(signerId, {
    kind: "os-cert",
    signer,
  });

  return {
    signerId,
    metadata: signer.metadata,
  };
}

/**
 * Sign data using an active OS cert signer.
 *
 * @param signerId - The signer ID from oscertConnect.
 * @param data - The data to sign (raw bytes).
 * @returns The raw r||s signature (64 bytes for P-256).
 * @throws Error if the signerId is not found.
 */
export async function oscertSign(
  signerId: string,
  data: Uint8Array,
): Promise<Uint8Array> {
  const managed = sessions.get(signerId);
  if (!managed) {
    throw new Error("Signer not found — session may have been disconnected");
  }

  return managed.signer.sign(data);
}

/**
 * Disconnect an OS cert signer.
 *
 * @param signerId - The signer ID from oscertConnect.
 */
export function oscertDisconnect(signerId: string): void {
  if (!sessions.has(signerId)) {
    return; // Already disconnected or never connected
  }
  sessions.delete(signerId);
}

// ---------------------------------------------------------------------------
// Accessor (for testing)
// ---------------------------------------------------------------------------

/**
 * Get an active signer by ID.
 *
 * @param signerId - The signer ID.
 * @returns The Signer, or undefined if not found.
 */
export function getSigner(signerId: string): Signer | undefined {
  return sessions.get(signerId)?.signer;
}

/**
 * Get the number of active sessions (for testing/monitoring).
 */
export function getActiveSessionCount(): number {
  return sessions.size;
}

/**
 * Disconnect all active sessions. Used during shutdown.
 */
export function disconnectAll(): void {
  const signerIds = [...sessions.keys()];
  for (const signerId of signerIds) {
    const managed = sessions.get(signerId);
    if (!managed) continue;
    if (managed.kind === "pkcs11") {
      pkcs11Disconnect(signerId);
    } else {
      oscertDisconnect(signerId);
    }
  }
}
