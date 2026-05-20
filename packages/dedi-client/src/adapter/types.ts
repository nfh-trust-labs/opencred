import type { DeDiApiClientConfig } from "../api/api-client.js";

export interface DeDiClientConfig extends DeDiApiClientConfig {
  defaultNamespace?: string;
}

/**
 * Result of a revocation lookup or publish. DeDi's canonical `revoke` tag
 * uses record existence to signify revocation — there is no boolean flag
 * inside `details`. Schema: https://dedi.global/revoke.json
 *
 * - `revoked: true`  ⇒ a record exists; `revokedAt` is the envelope's
 *   `updated_at`, `reason` is the optional reason supplied at publish time
 * - `revoked: false` ⇒ no record exists
 */
export type RevocationHashRecord =
  | { revoked: true; revokedAt: string; reason?: string }
  | { revoked: false };

export interface DIDRecord {
  did: string;
  document: unknown;
  resolvedAt: string;
  /**
   * Optional attribution metadata describing the organisation that
   * controls this DID. Populated when the issuer (or DeDi operator) has
   * supplied a display name / contact info alongside the DID document.
   * Absent records still resolve correctly; verifiers should treat
   * "metadata missing" as "unattributed" rather than as an error.
   */
  metadata?: {
    /** Human-readable organisation name displayed by the verifier UI. */
    orgName?: string;
    /** Optional contact (URL, email, etc.) for the organisation. */
    contact?: string;
    /**
     * Optional verified domain claim — used as a stronger attribution
     * signal than `orgName` alone. May be set when DeDi has verified
     * control of the domain (e.g. via DNS TXT). The verifier UI should
     * surface this distinctly from unverified `orgName`.
     */
    verifiedDomain?: string;
  };
  /**
   * If this DID has been superseded by a successor (e.g. because the
   * issuer rotated to a new did:key), this points at the new DID. The
   * verifier's key-supersession check uses this to flag credentials
   * issued under the old DID as stale even though they remain
   * cryptographically valid.
   */
  supersededBy?: {
    did: string;
    /** When the supersession was published. ISO 8601. */
    at: string;
    /** Optional human-readable reason (e.g. "annual rotation"). */
    reason?: string;
  };
}

export interface SchemaRecord {
  schemaId: string;
  version: string;
  schema: Record<string, unknown>;
  contextUrl?: string;
  checksum: string;
  publishedAt: string;
}

export interface ContextRecord {
  schemaId: string;
  version: string;
  context: Record<string, unknown>;
  publishedAt: string;
}

export interface PublishResult {
  published: boolean;
  recordName: string;
  namespace: string;
}
