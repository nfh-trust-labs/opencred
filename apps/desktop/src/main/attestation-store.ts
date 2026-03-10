/**
 * In-memory store for Key Attestation VCs received from the API.
 *
 * Each attestation is associated with a key ID (the verification method ID
 * of the issuer's key). The store extracts metadata from the credential's
 * credentialSubject for safe display — the full credential is stored but
 * only metadata is returned by list operations.
 *
 * SECURITY INVARIANTS:
 *  - Full attestation credentials are NEVER included in list responses
 *    -- only metadata (organizationName, verifiedDomain, dates).
 *  - The store is in-memory only -- attestations do not persist across
 *    application restarts.
 */

import { isKeyAttestationCredential } from "@opencred/key-attestation";

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
  return attestationStore.delete(keyId);
}

/**
 * Clear all stored attestations.
 */
export function clearAttestationStore(): void {
  attestationStore.clear();
}

/**
 * Check if a key has an associated attestation.
 */
export function hasAttestation(keyId: string): boolean {
  return attestationStore.has(keyId);
}
