/**
 * Store for Key Attestation VCs received from the API.
 *
 * The in-memory Map is the primary read path for fast lookups.
 * On every mutation the full list is persisted to electron-store so that
 * attestations survive application restarts (they are valid for months).
 *
 * On startup, {@link loadPersistedAttestations} reads the persisted list,
 * prunes expired / structurally invalid entries, and populates the Map.
 *
 * SECURITY INVARIANTS:
 *  - Full attestation credentials are NEVER included in list responses
 *    -- only metadata (organizationName, verifiedDomain, dates).
 *  - Credential content is NEVER logged — only counts and key IDs.
 *  - electron-store handles encryption; file permissions are restricted
 *    to 0o600 by restrictStoreFilePermissions().
 */

import { isKeyAttestationCredential } from "@opencred/key-attestation";
import { getStore } from "./store.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StoredAttestation {
  /** The key ID this attestation is for (verificationMethodId). */
  keyId: string;
  /** The full signed Key Attestation VC. */
  credential: Record<string, unknown>;
  /** When the attestation was stored (ISO 8601). */
  storedAt: string;
  /** Organization name from the attestation. */
  organizationName: string;
  /** Verified domain from identity verification. */
  verifiedDomain: string;
  /** Attestation validity period start (ISO 8601). */
  validFrom: string;
  /** Attestation validity period end (ISO 8601). */
  validUntil: string;
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

const attestationStore = new Map<string, StoredAttestation>();

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------

/**
 * Write the current in-memory attestations to electron-store.
 */
function persistToStore(): void {
  try {
    const store = getStore();
    store.set("attestations", Array.from(attestationStore.values()));
  } catch {
    // Store may not be initialised yet (e.g. during early startup or tests).
    // Silently ignore — the in-memory map is the authoritative source and
    // persistence will catch up on the next mutation after init.
  }
}

// ---------------------------------------------------------------------------
// Metadata extraction
// ---------------------------------------------------------------------------

/**
 * Extract metadata from a Key Attestation credential's credentialSubject.
 *
 * The credential structure follows the KeyAttestationCredential type from
 * @opencred/key-attestation. The credentialSubject contains:
 *   - organizationName: string
 *   - identityVerification.verifiedDomain: string
 *
 * validFrom and validUntil are top-level fields on the credential.
 */
function extractMetadata(credential: Record<string, unknown>): {
  organizationName: string;
  verifiedDomain: string;
  validFrom: string;
  validUntil: string;
} {
  const subject = credential["credentialSubject"] as Record<string, unknown> | undefined;

  const organizationName = typeof subject?.["organizationName"] === "string"
    ? subject["organizationName"]
    : "";

  const identityVerification = subject?.["identityVerification"] as Record<string, unknown> | undefined;
  const verifiedDomain = typeof identityVerification?.["verifiedDomain"] === "string"
    ? identityVerification["verifiedDomain"]
    : "";

  const validFrom = typeof credential["validFrom"] === "string"
    ? credential["validFrom"]
    : "";

  const validUntil = typeof credential["validUntil"] === "string"
    ? credential["validUntil"]
    : "";

  return { organizationName, verifiedDomain, validFrom, validUntil };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Store a Key Attestation VC.
 *
 * @param keyId - The verification method ID of the key this attestation is for.
 * @param credential - The full signed Key Attestation VC.
 * @returns The stored attestation with extracted metadata.
 * @throws {Error} If the credential is not a valid KeyAttestationCredential.
 */
export function storeAttestation(
  keyId: string,
  credential: Record<string, unknown>,
): StoredAttestation {
  if (!isKeyAttestationCredential(credential)) {
    throw new Error("Invalid credential: not a KeyAttestationCredential");
  }

  const metadata = extractMetadata(credential);

  const stored: StoredAttestation = {
    keyId,
    credential,
    storedAt: new Date().toISOString(),
    organizationName: metadata.organizationName,
    verifiedDomain: metadata.verifiedDomain,
    validFrom: metadata.validFrom,
    validUntil: metadata.validUntil,
  };

  attestationStore.set(keyId, stored);
  persistToStore();
  return stored;
}

/**
 * Retrieve a stored attestation by key ID.
 */
export function getAttestation(keyId: string): StoredAttestation | undefined {
  return attestationStore.get(keyId);
}

/**
 * List all stored attestations.
 *
 * Returns the full StoredAttestation objects. Callers that expose data
 * to the renderer process should strip the `credential` field and
 * return only metadata.
 */
export function listAttestations(): StoredAttestation[] {
  return Array.from(attestationStore.values());
}

/**
 * Remove an attestation by key ID.
 *
 * @returns true if the attestation was found and removed, false otherwise.
 */
export function removeAttestation(keyId: string): boolean {
  const removed = attestationStore.delete(keyId);
  if (removed) {
    persistToStore();
  }
  return removed;
}

/**
 * Clear all stored attestations.
 */
export function clearAttestationStore(): void {
  attestationStore.clear();
  persistToStore();
}

/**
 * Check if a key has an associated attestation.
 */
export function hasAttestation(keyId: string): boolean {
  return attestationStore.has(keyId);
}

// ---------------------------------------------------------------------------
// Startup loading
// ---------------------------------------------------------------------------

/**
 * Load persisted attestations from electron-store into the in-memory Map.
 *
 * Called once during app startup after {@link initStore}. For each persisted
 * attestation the function validates:
 *   1. The `validUntil` date has not passed (prune expired).
 *   2. The credential passes {@link isKeyAttestationCredential} (prune invalid).
 *
 * After loading, the pruned list (expired / invalid entries removed) is
 * written back to electron-store.
 *
 * Only counts and key IDs are logged — never credential content.
 */
export function loadPersistedAttestations(): void {
  try {
    const store = getStore();
    const persisted: StoredAttestation[] = store.get("attestations") ?? [];

    if (persisted.length === 0) {
      console.log("[attestation-store] No persisted attestations found.");
      return;
    }

    const now = new Date();
    let loaded = 0;
    let prunedExpired = 0;
    let prunedInvalid = 0;

    for (const entry of persisted) {
      // Validate structure
      if (
        !entry ||
        typeof entry.keyId !== "string" ||
        !entry.credential ||
        !isKeyAttestationCredential(entry.credential)
      ) {
        prunedInvalid++;
        continue;
      }

      // Validate expiry
      if (entry.validUntil) {
        const expiryDate = new Date(entry.validUntil);
        if (!isNaN(expiryDate.getTime()) && expiryDate <= now) {
          prunedExpired++;
          console.log(
            `[attestation-store] Pruned expired attestation for key: ${entry.keyId}`,
          );
          continue;
        }
      }

      attestationStore.set(entry.keyId, entry);
      loaded++;
    }

    // Write back pruned list
    const prunedTotal = prunedExpired + prunedInvalid;
    if (prunedTotal > 0) {
      store.set("attestations", Array.from(attestationStore.values()));
    }

    console.log(
      `[attestation-store] Loaded ${loaded} attestation(s) from disk.` +
        (prunedTotal > 0
          ? ` Pruned ${prunedExpired} expired, ${prunedInvalid} invalid.`
          : ""),
    );
  } catch (err: unknown) {
    console.error(
      "[attestation-store] Failed to load persisted attestations:",
      err instanceof Error ? err.message : String(err),
    );
  }
}
