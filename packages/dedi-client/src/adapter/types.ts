import type { DeDiApiClientConfig } from "../api/api-client.js";
import type { DeDiProof } from "../api/types.js";

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
 * Lifecycle status of a signing key in the `opencred-key-registry`.
 *
 * - `active`  — the key is in current use; credentials signed by it verify.
 * - `rotated` — the key was cleanly retired (the issuer moved to a new
 *               key). Credentials signed by it *remain valid* — a clean
 *               rotation implies the old key was never compromised, so
 *               there are no forgeries to invalidate.
 * - `revoked` — the key is compromised / withdrawn. The verifier rejects
 *               every credential signed by it (top-level `REVOKED`),
 *               because once a key is compromised no signature it produced
 *               can be trusted, regardless of when it was made.
 *
 * The transition is monotone and terminal at `revoked`:
 * `active → rotated → revoked`, never backward. No timestamps /
 * validity windows are stored — revocation makes them unnecessary (see
 * the F1 analysis in `docs/decisions/dedi-key-registry-redesign.md`).
 */
export type KeyStatus = "active" | "rotated" | "revoked";

/**
 * Per-key registry record — the `opencred-key-registry` payload, one
 * record per signing key. This is DeDi's canonical "one record per key"
 * model and the source of truth for "is this key live?".
 *
 * - `keyId`         — the verification method, i.e. the key's full `id`
 *                     (`did:web:acme.com#key-0`, or a `did:key:...#z...`
 *                     fragment). Also the basis for the record name.
 * - `controllerDid` — the DID that controls the key (`keyId.split("#")[0]`).
 *                     Baking the DID into each record means keys from
 *                     different DIDs under one namespace never collide.
 * - `algorithm`     — the key algorithm label (e.g. `Ed25519`, `ES256`).
 * - `publicKeyJwk`  — the public key material as a JWK. Public only —
 *                     never a private `d` member.
 * - `purpose`       — the verification relationships the key serves
 *                     (e.g. `["assertionMethod"]`).
 * - `status`        — {@link KeyStatus}.
 *
 * Concurrency invariant — read before adding fields. DeDi's
 * `update-record` has no optimistic-lock parameter, so `setKeyStatus`
 * is safe under concurrent writes only because the only mutable field,
 * `status`, transitions monotonically (`active → rotated → revoked`) and
 * converges. Every other field is immutable for the life of the record
 * (a new key is a new record). Any new field that can diverge between
 * concurrent writers would reintroduce the lost-update race — close it
 * at the DeDi side first.
 */
export interface KeyRecord {
  keyId: string;
  controllerDid: string;
  algorithm: string;
  publicKeyJwk: Record<string, unknown>;
  purpose: string[];
  status: KeyStatus;
  /**
   * CORD-blockchain anchor metadata copied off the DeDi envelope by the
   * adapter. Not part of the published `details` payload — DeDi sets this
   * server-side and surfaces it on lookup responses. Verifier callers use
   * it to confirm the record was anchored on-chain by the claimed creator
   * DID; absence simply means DeDi did not include a proof in this
   * response.
   */
  proof?: DeDiProof;
}

/**
 * DeDi-hosted DID document record — the `did-documents` registry payload,
 * one record per DID. Stores the assembled W3C `did.json` so DeDi can host
 * a no-webserver issuer's did:web document and back the did:web fallback
 * resolver.
 *
 * - `did`      — the DID this document describes (required).
 * - `document` — the full W3C DID Document (required; this registry only
 *                exists to hold documents).
 *
 * Unlike {@link KeyRecord}, this record is *mutable*: every rotation /
 * revocation regenerates the document (adding the new key, dropping a
 * revoked key) and re-publishes it here. `publishDidDocument` is therefore
 * upsert — it updates an existing record rather than failing on collision.
 */
export interface DidDocumentRecord {
  did: string;
  document: Record<string, unknown>;
  /** See {@link KeyRecord.proof}. */
  proof?: DeDiProof;
}

export interface SchemaRecord {
  schemaId: string;
  version: string;
  schema: Record<string, unknown>;
  contextUrl?: string;
  checksum: string;
  publishedAt: string;
  /** See {@link KeyRecord.proof}. */
  proof?: DeDiProof;
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

/**
 * Result of a `setKeyStatus` transition.
 *
 * - `changed: true`  — the record's `status` was advanced and written
 *   back to DeDi. `from`/`to` describe the transition.
 * - `changed: false` — idempotent short-circuit. The record was already
 *   at (or past) the target status, so no write was issued. `reason`
 *   distinguishes "already there" from "refused to move backward".
 */
export type SetKeyStatusResult =
  | { changed: true; keyId: string; from: KeyStatus; to: KeyStatus; namespace: string }
  | {
      changed: false;
      keyId: string;
      status: KeyStatus;
      reason: "already-at-status" | "monotone-refused";
      namespace: string;
    };
