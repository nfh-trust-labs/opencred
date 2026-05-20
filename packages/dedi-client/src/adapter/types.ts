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

/**
 * DID registry record — the public-key registry payload stored in DeDi
 * under `public_key_registry`.
 *
 * Schema (3 fields):
 * - `did`        — the DID string this record represents (required).
 * - `document`   — the W3C DID Document. Omitted for `did:key` because
 *                  the verifier derives it from the DID itself via the
 *                  did:key resolution algorithm. Required for `did:web`
 *                  records, where DeDi acts as a cache for the
 *                  domain-hosted `.well-known/did.json`.
 * - `keyStatus`  — `"current"` while the key is in active use, flipped to
 *                  `"rotated"` by `markDIDRotated` when the issuer
 *                  publishes a new key. The signature on credentials
 *                  signed under a rotated key remains cryptographically
 *                  valid; the flag is advisory to verifier UIs.
 *
 * Concurrency invariant — read before adding fields. DeDi's
 * `update-record` has no optimistic-lock parameter, so `markDIDRotated`
 * is safe under concurrent writes only because every mutable transition
 * on this record is monotone and convergent: `keyStatus` flips
 * `current` → `rotated` once and never back, `did` is the record key,
 * and `document` is written only by `publishDID`. Any new field that
 * can diverge between concurrent writers (e.g. `rotatedAt` timestamp,
 * `supersededBy` chain, multi-key state) would reintroduce the
 * lost-update race — close it at the DeDi side first.
 */
export interface DIDRecord {
  did: string;
  document?: Record<string, unknown>;
  keyStatus: "current" | "rotated";
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
