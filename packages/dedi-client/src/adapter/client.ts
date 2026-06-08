import { DeDiClientError, DeDiRecordExistsError } from "@opencred/shared";
import { DeDiApiClient } from "../api/api-client.js";
import type { DeDiProof } from "../api/types.js";
import type { DeDiLogger } from "../logger.js";
import { noopLogger } from "../logger.js";
import type {
  DeDiClientConfig,
  RevocationHashRecord,
  KeyRecord,
  KeyStatus,
  DidDocumentRecord,
  SchemaRecord,
  ContextRecord,
  PublishResult,
  SetKeyStatusResult,
} from "./types.js";
import {
  REVOCATION_REGISTRY,
  OPENCRED_KEY_REGISTRY,
  DID_DOCUMENTS_REGISTRY,
  SCHEMA_REGISTRY,
  CONTEXT_REGISTRY,
  schemaToRecordName,
  contextToRecordName,
  didToRecordName,
  verificationMethodToRecordName,
} from "./registry-names.js";

/**
 * Monotone rank for {@link KeyStatus} transitions: `active(0) → rotated(1)
 * → revoked(2)`. `setKeyStatus` only ever advances rank — it never moves a
 * key backward (you can't un-revoke or un-rotate a key), which is what
 * makes concurrent transitions race-safe against DeDi's lock-free
 * `update-record`.
 */
const KEY_STATUS_RANK: Record<KeyStatus, number> = {
  active: 0,
  rotated: 1,
  revoked: 2,
};

const KEY_STATUSES: readonly KeyStatus[] = ["active", "rotated", "revoked"];

/**
 * Validate an `opencred-key-registry` payload against the per-key schema:
 * `{ keyId, controllerDid, algorithm, publicKeyJwk, purpose, status }`.
 *
 * `status` is a strict enum — anything outside {@link KEY_STATUSES} is a
 * server-side bug (502) because the verifier's accept/reject decision keys
 * off it. `publicKeyJwk` must be an object; `purpose` must be an array of
 * strings.
 */
function assertKeyRecordShape(detail: unknown): asserts detail is KeyRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("Key record detail is missing or not an object", 502);
  }
  const rec = detail as Record<string, unknown>;
  if (typeof rec["keyId"] !== "string") {
    throw new DeDiClientError("Key record detail missing required field: keyId", 502);
  }
  if (typeof rec["controllerDid"] !== "string") {
    throw new DeDiClientError("Key record detail missing required field: controllerDid", 502);
  }
  if (typeof rec["algorithm"] !== "string") {
    throw new DeDiClientError("Key record detail missing required field: algorithm", 502);
  }
  if (rec["publicKeyJwk"] == null || typeof rec["publicKeyJwk"] !== "object") {
    throw new DeDiClientError("Key record detail field 'publicKeyJwk' must be an object", 502);
  }
  if (
    !Array.isArray(rec["purpose"]) ||
    !(rec["purpose"] as unknown[]).every((p) => typeof p === "string")
  ) {
    throw new DeDiClientError("Key record detail field 'purpose' must be an array of strings", 502);
  }
  if (!KEY_STATUSES.includes(rec["status"] as KeyStatus)) {
    throw new DeDiClientError(
      "Key record detail field 'status' must be 'active', 'rotated', or 'revoked'",
      502,
    );
  }
}

/**
 * Validate a `did-documents` payload against the 2-field schema:
 * `{ did, document }`. Both are required — this registry exists solely to
 * hold DID documents. The `document` is validated only as "an object";
 * the downstream verifier enforces the W3C DID-Document contract.
 */
function assertDidDocumentRecordShape(detail: unknown): asserts detail is DidDocumentRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("DID document record detail is missing or not an object", 502);
  }
  const rec = detail as Record<string, unknown>;
  if (typeof rec["did"] !== "string") {
    throw new DeDiClientError("DID document record detail missing required field: did", 502);
  }
  if (rec["document"] == null || typeof rec["document"] !== "object") {
    throw new DeDiClientError("DID document record detail field 'document' must be an object", 502);
  }
}

const SCHEMA_RECORD_KEYS = ["schemaId", "version", "schema", "checksum", "publishedAt"] as const;

function assertSchemaRecordShape(detail: unknown): asserts detail is SchemaRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("Schema record detail is missing or not an object", 502);
  }
  const rec = detail as Record<string, unknown>;
  for (const key of SCHEMA_RECORD_KEYS) {
    if (!(key in rec)) {
      throw new DeDiClientError(`Schema record detail missing required field: ${key}`, 502);
    }
  }
  if (typeof rec["schemaId"] !== "string") {
    throw new DeDiClientError("Schema record field 'schemaId' must be a string", 502);
  }
  if (typeof rec["version"] !== "string") {
    throw new DeDiClientError("Schema record field 'version' must be a string", 502);
  }
  if (rec["schema"] == null || typeof rec["schema"] !== "object") {
    throw new DeDiClientError("Schema record field 'schema' must be an object", 502);
  }
  if (typeof rec["checksum"] !== "string") {
    throw new DeDiClientError("Schema record field 'checksum' must be a string", 502);
  }
  if (typeof rec["publishedAt"] !== "string") {
    throw new DeDiClientError("Schema record field 'publishedAt' must be a string", 502);
  }
}

const CONTEXT_RECORD_KEYS = ["schemaId", "version", "context", "publishedAt"] as const;

function assertContextRecordShape(detail: unknown): asserts detail is ContextRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("Context record detail is missing or not an object", 502);
  }
  const rec = detail as Record<string, unknown>;
  for (const key of CONTEXT_RECORD_KEYS) {
    if (!(key in rec)) {
      throw new DeDiClientError(`Context record detail missing required field: ${key}`, 502);
    }
  }
  if (typeof rec["schemaId"] !== "string") {
    throw new DeDiClientError("Context record field 'schemaId' must be a string", 502);
  }
  if (typeof rec["version"] !== "string") {
    throw new DeDiClientError("Context record field 'version' must be a string", 502);
  }
  if (rec["context"] == null || typeof rec["context"] !== "object") {
    throw new DeDiClientError("Context record field 'context' must be an object", 502);
  }
  if (typeof rec["publishedAt"] !== "string") {
    throw new DeDiClientError("Context record field 'publishedAt' must be a string", 502);
  }
}

/**
 * Validate that a single DeDi record (the inner payload, not the
 * `{ message, data }` wrapper) has the required top-level fields.
 * Reused by `assertDeDiRecordShape` for the envelope path and directly
 * for search-result entries (which arrive as bare records inside
 * `data: DeDiRecord[]`).
 */
function assertDeDiRecordPayload(
  value: unknown,
  label: string,
): asserts value is { record_name: string; details: unknown } {
  if (value == null || typeof value !== "object") {
    throw new DeDiClientError(`DeDi API ${label} response is missing or not an object`, 502);
  }
  const rec = value as Record<string, unknown>;
  if (typeof rec["record_name"] !== "string") {
    throw new DeDiClientError(
      `DeDi API ${label} response missing required field: record_name`,
      502,
    );
  }
  if (!("details" in rec)) {
    throw new DeDiClientError(`DeDi API ${label} response missing required field: details`, 502);
  }
}

/**
 * Validate that a response from `publishRecord` / `lookupRecord` matches
 * the real DeDi envelope shape — `{ message, data: { record_name,
 * details, ... } }`. Verified against the `develop` Postman collection
 * on 2026-05-19. Callers extract `response.data.details` to get the
 * OpenCred payload after this check.
 */
function assertDeDiRecordShape(
  value: unknown,
  label: string,
): asserts value is { message: string; data: { record_name: string; details: unknown } } {
  if (value == null || typeof value !== "object") {
    throw new DeDiClientError(`DeDi API ${label} response is missing or not an object`, 502);
  }
  const env = value as Record<string, unknown>;
  if (!("data" in env)) {
    throw new DeDiClientError(`DeDi API ${label} response missing required field: data`, 502);
  }
  assertDeDiRecordPayload(env["data"], `${label} data`);
}

/**
 * Extract the CORD-anchor `proof` block from a DeDi envelope's `data`
 * payload. Returns `undefined` when the field is absent, malformed, or
 * missing required string members. Verifier code treats absence as
 * "no anchor info available" (advisory) rather than an error — DeDi
 * historically returned envelopes without proof, and we don't want a
 * non-conforming envelope to block verification of an otherwise valid
 * credential.
 *
 * `network_genesis` is `string | null` on the wire (a record may not be
 * anchored to a specific network) so we accept both. Any other unexpected
 * shape is dropped silently.
 */
function extractProof(envelopeData: unknown): DeDiProof | undefined {
  if (envelopeData == null || typeof envelopeData !== "object") return undefined;
  const proof = (envelopeData as Record<string, unknown>)["proof"];
  if (proof == null || typeof proof !== "object") return undefined;
  const p = proof as Record<string, unknown>;
  if (
    typeof p["type"] !== "string" ||
    typeof p["namespace_did"] !== "string" ||
    typeof p["creator_did"] !== "string" ||
    typeof p["digest"] !== "string"
  ) {
    return undefined;
  }
  if (
    p["network_genesis"] !== null &&
    p["network_genesis"] !== undefined &&
    typeof p["network_genesis"] !== "string"
  ) {
    return undefined;
  }
  const result: DeDiProof = {
    type: p["type"],
    namespace_did: p["namespace_did"],
    creator_did: p["creator_did"],
    digest: p["digest"],
    network_genesis: (p["network_genesis"] as string | null | undefined) ?? null,
  };
  if (typeof p["registry_identifier"] === "string") {
    result.registry_identifier = p["registry_identifier"];
  }
  if (typeof p["record_identifier"] === "string") {
    result.record_identifier = p["record_identifier"];
  }
  return result;
}

export class DeDiClient {
  private readonly api: DeDiApiClient;
  private readonly defaultNamespace?: string;
  readonly logger: DeDiLogger;

  constructor(config: DeDiClientConfig) {
    this.api = new DeDiApiClient(config);
    this.defaultNamespace = config.defaultNamespace;
    this.logger = config.logger ?? noopLogger;
  }

  get apiClient(): DeDiApiClient {
    return this.api;
  }

  /**
   * Publish a revocation entry to the `vc-revocation-registry` (DeDi
   * canonical `revoke` tag). Payload matches https://dedi.global/revoke.json:
   * `{ revoked_id, reason? }`. Record existence ⇒ revoked; there is no
   * boolean flag inside `details`.
   */
  async publishRevocationHash(
    hash: string,
    namespace?: string,
    reason?: string,
  ): Promise<RevocationHashRecord> {
    const ns = this.resolveNamespace(namespace);
    const detailsToPublish: { revoked_id: string; reason?: string } = { revoked_id: hash };
    if (reason !== undefined) detailsToPublish.reason = reason;
    let response;
    try {
      response = await this.api.publishRecord(ns, REVOCATION_REGISTRY, hash, detailsToPublish);
    } catch (err) {
      // DeDi returns 409 "duplicate record name" when the hash is already
      // published. Surface this as a specific error so HTTP clients can
      // distinguish "already revoked" (success-after-prior-run) from
      // generic DeDi failures. See {@link isDuplicateRecordBody}.
      if (isDuplicateRecordBody(err)) {
        throw new DeDiRecordExistsError(
          "This hash is already in the revocation registry",
          "Use POST /v1/credentials/revocation-status to confirm the prior revoke landed",
          (err as DeDiClientError).responseBody,
        );
      }
      throw err;
    }
    assertDeDiRecordShape(response, "publishRecord");
    // Post-publish, the record exists ⇒ revoked. Use the envelope's
    // `updated_at` as the revocation timestamp (DeDi's canonical answer
    // to "when did this record reach its current state"). The assert
    // narrows the envelope to a minimal `{ record_name, details }` shape
    // for safety, but the real wire type carries `updated_at`; fall back
    // to "now" if a non-conforming DeDi build omits it.
    const data = response.data as { record_name: string; details: unknown; updated_at?: string };
    return {
      revoked: true,
      revokedAt: data.updated_at ?? new Date().toISOString(),
      ...(reason !== undefined ? { reason } : {}),
    };
  }

  /**
   * Query the `vc-revocation-registry` for a record keyed by VC hash.
   * Record existence ⇒ revoked (DeDi canonical "Revoke" tag semantics).
   * Returns `{ revoked: false }` when no record is found.
   *
   * Uses direct `lookupRecord` because `publishRevocationHash` writes the
   * hash as the record_name (so the hash is the primary key, not just a
   * details field). The earlier `/dedi/search` path returned empty `data`
   * for `details.revoked_id` filters on api.dedi.global — a separate
   * issue, but moot since the direct lookup is both correct and faster.
   */
  async queryRevocationHash(hash: string, namespace?: string): Promise<RevocationHashRecord> {
    const ns = this.resolveNamespace(namespace);

    let response;
    try {
      response = await this.api.lookupRecord(ns, REVOCATION_REGISTRY, hash);
    } catch (err) {
      if (err instanceof DeDiClientError && err.statusCode === 404) {
        return { revoked: false };
      }
      throw err;
    }
    assertDeDiRecordShape(response, "lookupRecord");

    // The full record envelope carries `updated_at`; fall back to "" when
    // a non-conforming DeDi build omits it.
    const data = response.data as { record_name: string; details: unknown; updated_at?: string };
    const details = data.details as Record<string, unknown> | null | undefined;
    const reason =
      details && typeof details["reason"] === "string" ? (details["reason"] as string) : undefined;
    return {
      revoked: true,
      revokedAt: data.updated_at ?? "",
      ...(reason !== undefined ? { reason } : {}),
    };
  }

  /**
   * Publish a signing key to the `opencred-key-registry`.
   *
   * One record per key (DeDi's canonical "one record per key" model),
   * keyed by `verificationMethodToRecordName(key.keyId)`. The published
   * payload is the full {@link KeyRecord} minus the server-set `proof`.
   * Records are immutable except for `status` — a new key is always a new
   * record, never an overwrite — so a duplicate record name means "this
   * exact key was already published", which we surface as a
   * {@link DeDiRecordExistsError} (callers treat it as benign).
   *
   * New keys should be published with `status: "active"`. The lifecycle
   * (`active → rotated → revoked`) is advanced later via
   * {@link setKeyStatus}.
   *
   * The caller owns key material; this method only ever sees the public
   * `publicKeyJwk`. It never accepts, transmits, or stores a private key.
   */
  async publishKey(key: KeyRecord, namespace?: string): Promise<PublishResult> {
    const ns = this.resolveNamespace(namespace);
    const recordName = verificationMethodToRecordName(key.keyId);

    // Strip any server-set `proof` before publishing — `details` is the
    // issuer-authored payload only.
    const detail = {
      keyId: key.keyId,
      controllerDid: key.controllerDid,
      algorithm: key.algorithm,
      publicKeyJwk: key.publicKeyJwk,
      purpose: key.purpose,
      status: key.status,
    };

    try {
      await this.api.publishRecord(ns, OPENCRED_KEY_REGISTRY, recordName, detail);
    } catch (err) {
      if (isDuplicateRecordBody(err)) {
        throw new DeDiRecordExistsError(
          "This key is already in the key registry",
          "Use POST /v1/keys/resolve to fetch the existing record",
          (err as DeDiClientError).responseBody,
        );
      }
      throw err;
    }
    return { published: true, recordName, namespace: ns };
  }

  /**
   * Resolve a signing key's record from the `opencred-key-registry` by its
   * verification method (the key's full `id`). This is the call a verifier
   * makes to answer "is this key live?" — see {@link KeyStatus}.
   */
  async resolveKey(verificationMethod: string, namespace?: string): Promise<KeyRecord> {
    const ns = this.resolveNamespace(namespace);
    const recordName = verificationMethodToRecordName(verificationMethod);
    const response = await this.api.lookupRecord(ns, OPENCRED_KEY_REGISTRY, recordName);
    assertDeDiRecordShape(response, "lookupRecord");
    const details = response.data.details;
    assertKeyRecordShape(details);
    // Surface the DeDi `version` envelope field (a string on the wire, e.g.
    // "1") at debug. No behavior change today — but it positions
    // `setKeyStatus` to adopt a conditional/CAS `update-record` keyed on
    // `version` if DeDi ever exposes one (issue #659, Option A). Only the
    // public verification-method id and status are logged — never key
    // material (CLAUDE.md: "Log the key ID or fingerprint, never the key
    // itself"). The narrowing `assert` drops `version` from the static type,
    // so read it through a cast (the wire type carries it — `DeDiRecord`).
    const version = (response.data as { version?: string }).version;
    this.logger.debug("Resolved key record", {
      keyId: verificationMethod,
      status: details.status,
      namespace: ns,
      version: version ?? null,
    });
    const proof = extractProof(response.data);
    return proof ? { ...details, proof } : details;
  }

  /**
   * Advance a key's lifecycle status in the `opencred-key-registry`.
   *
   * The transition is **monotone**: `active → rotated → revoked`, and only
   * ever forward. This is what makes it race-safe against DeDi's lock-free
   * `update-record` — concurrent writers converge because no caller ever
   * moves a key backward, and the only mutable field is `status`. A request
   * to move backward (e.g. `revoked → rotated`) or to set the status it's
   * already at is a no-op (`changed: false`), not an error.
   *
   * - `rotated`: clean retirement. Credentials signed by the key stay
   *   valid (a clean rotation means the key was never compromised).
   * - `revoked`: compromise / withdrawal. The verifier rejects every
   *   credential signed by the key (top-level `REVOKED`).
   *
   * Throws (via `resolveKey`) if the key has no record yet — you can't
   * change the status of a key you never published.
   */
  async setKeyStatus(
    verificationMethod: string,
    status: KeyStatus,
    namespace?: string,
  ): Promise<SetKeyStatusResult> {
    // Guard against an out-of-enum status reaching the monotone comparison —
    // `KEY_STATUS_RANK[<garbage>]` is `undefined`, which fails both the
    // equality and `<` checks and would otherwise fall through and write the
    // bogus status to DeDi. Fail fast (400) instead.
    if (!KEY_STATUSES.includes(status)) {
      throw new DeDiClientError(
        `setKeyStatus: invalid status '${String(status)}' (expected ${KEY_STATUSES.join(" | ")})`,
        400,
      );
    }
    const ns = this.resolveNamespace(namespace);
    const recordName = verificationMethodToRecordName(verificationMethod);
    const existing = await this.resolveKey(verificationMethod, ns);

    const currentRank = KEY_STATUS_RANK[existing.status];
    const targetRank = KEY_STATUS_RANK[status];

    if (targetRank === currentRank) {
      this.logger.info("Key already at requested status; skipping update-record", {
        keyId: verificationMethod,
        status,
        namespace: ns,
      });
      return {
        changed: false,
        keyId: verificationMethod,
        status: existing.status,
        reason: "already-at-status",
        namespace: ns,
      };
    }
    if (targetRank < currentRank) {
      this.logger.warn("Refusing to move key status backward (monotone invariant)", {
        keyId: verificationMethod,
        from: existing.status,
        to: status,
        namespace: ns,
      });
      return {
        changed: false,
        keyId: verificationMethod,
        status: existing.status,
        reason: "monotone-refused",
        namespace: ns,
      };
    }

    // ── Optimistic-concurrency note (issue #659) ─────────────────────────
    // DeDi's `update-record` takes no conditional-update parameter (no
    // If-Match / ETag / version CAS), so this is a *blind* last-writer-wins
    // overwrite of the whole payload. `status` is the single mutable field and
    // it advances monotonically (active → rotated → revoked); the rank guard
    // above refuses any move backward from the state THIS caller observed.
    // That makes `revoked` terminal once observed — no writer that has seen it
    // will downgrade it.
    //
    // It does NOT make blind concurrent writes fully race-free: two writers
    // that BOTH read the same pre-terminal state can each pass the guard and
    // race their writes, so a stale lower-rank write could land last and drop
    // a higher-rank update (a lost update). In practice per-key lifecycle ops
    // are normally causally ordered (you revoke a key you already know about),
    // so the window is small — but it is real, and closing it is exactly what
    // an Option-A version/ETag CAS would do.
    //
    // The single-mutable-field property is load-bearing. Adding ANY other mutable field to
    // `updatedDetails` (e.g. a `revokedAt` timestamp or a revocation
    // `reason`) reintroduces the lost-update race: two writers that diverge
    // on the new field would clobber each other under last-writer-wins.
    // Do not add fields here without first closing the race at the DeDi side.
    // A test in client.test.ts pins this payload to exactly the six fields.
    // TODO(#659): adopt a `version`/ETag conditional update once DeDi
    // supports one (Option A) — `resolveKey` already surfaces `version`.
    const updatedDetails: Omit<KeyRecord, "proof"> = {
      keyId: existing.keyId,
      controllerDid: existing.controllerDid,
      algorithm: existing.algorithm,
      publicKeyJwk: existing.publicKeyJwk,
      purpose: existing.purpose,
      status,
    };
    await this.api.updateRecord(ns, OPENCRED_KEY_REGISTRY, recordName, updatedDetails);
    this.logger.info("Key status advanced in DeDi", {
      keyId: verificationMethod,
      from: existing.status,
      to: status,
      namespace: ns,
    });
    return {
      changed: true,
      keyId: verificationMethod,
      from: existing.status,
      to: status,
      namespace: ns,
    };
  }

  /**
   * Publish (or re-publish) a DID document to the `did-documents`
   * registry, keyed by `didToRecordName(did)`.
   *
   * **Upsert semantics.** Unlike key records, a DID document is mutable:
   * every rotation/revocation regenerates `did.json` and republishes it
   * here. So a collision on the record name is handled by updating the
   * existing record rather than failing.
   *
   * This registry only exists to hold documents, so a `document` is
   * required. did:key issuers never need this (their document is derived
   * from the DID); the typical caller is a did:web issuer who has chosen
   * to let DeDi host their `did.json` instead of (or in addition to)
   * serving it from their own domain.
   */
  async publishDidDocument(
    did: string,
    document: unknown,
    namespace?: string,
  ): Promise<PublishResult> {
    const ns = this.resolveNamespace(namespace);
    const recordName = didToRecordName(did);

    if (document == null || typeof document !== "object") {
      throw new DeDiClientError("publishDidDocument: a DID Document object is required", 400);
    }

    const detail: DidDocumentRecord = { did, document: document as Record<string, unknown> };

    try {
      await this.api.publishRecord(ns, DID_DOCUMENTS_REGISTRY, recordName, detail);
    } catch (err) {
      // The document already exists — this is the rotation/revocation
      // re-publish path. Upsert: overwrite the prior document wholesale.
      if (isDuplicateRecordBody(err)) {
        await this.api.updateRecord(ns, DID_DOCUMENTS_REGISTRY, recordName, detail);
        this.logger.info("DID document updated in DeDi (upsert)", { did, namespace: ns });
        return { published: true, recordName, namespace: ns };
      }
      throw err;
    }
    return { published: true, recordName, namespace: ns };
  }

  /**
   * Resolve a DID document from the `did-documents` registry. Backs the
   * did:web fallback resolver: when an issuer's domain is unreachable, the
   * verifier reads the DeDi-hosted `did.json` from here.
   */
  async resolveDidDocument(did: string, namespace?: string): Promise<DidDocumentRecord> {
    const ns = this.resolveNamespace(namespace);
    const recordName = didToRecordName(did);
    const response = await this.api.lookupRecord(ns, DID_DOCUMENTS_REGISTRY, recordName);
    assertDeDiRecordShape(response, "lookupRecord");
    const details = response.data.details;
    assertDidDocumentRecordShape(details);
    const proof = extractProof(response.data);
    return proof ? { ...details, proof } : details;
  }

  async publishSchema(schema: SchemaRecord, namespace?: string): Promise<PublishResult> {
    const ns = this.resolveNamespace(namespace);
    const recordName = schemaToRecordName(schema.schemaId, schema.version);
    await this.api.publishRecord(ns, SCHEMA_REGISTRY, recordName, schema);
    return { published: true, recordName, namespace: ns };
  }

  async resolveSchema(
    schemaId: string,
    version: string,
    namespace?: string,
  ): Promise<SchemaRecord> {
    const ns = this.resolveNamespace(namespace);
    const recordName = schemaToRecordName(schemaId, version);
    const response = await this.api.lookupRecord(ns, SCHEMA_REGISTRY, recordName);
    assertDeDiRecordShape(response, "lookupRecord");
    const details = response.data.details;
    assertSchemaRecordShape(details);
    const proof = extractProof(response.data);
    return proof ? { ...details, proof } : details;
  }

  async publishContext(record: ContextRecord, namespace?: string): Promise<PublishResult> {
    const ns = this.resolveNamespace(namespace);
    const recordName = contextToRecordName(record.schemaId, record.version);
    await this.api.publishRecord(ns, CONTEXT_REGISTRY, recordName, record);
    return { published: true, recordName, namespace: ns };
  }

  async resolveContext(
    schemaId: string,
    version: string,
    namespace?: string,
  ): Promise<ContextRecord> {
    const ns = this.resolveNamespace(namespace);
    const recordName = contextToRecordName(schemaId, version);
    const response = await this.api.lookupRecord(ns, CONTEXT_REGISTRY, recordName);
    assertDeDiRecordShape(response, "lookupRecord");
    const details = response.data.details;
    assertContextRecordShape(details);
    return details;
  }

  async ensureRegistries(namespace: string): Promise<void> {
    // Lookup-first dedupe (see #546). createNamespace is non-idempotent and
    // has no `Idempotency-Key` support on the DeDi server; if we naively
    // POST every time we'd risk duplicating the row whenever the lookup
    // path is unreliable (transient 5xx, partial response, etc.). Checking
    // lookupNamespace first means a re-run of `ensureRegistries` against
    // an existing namespace is a single idempotent GET, not a POST.
    let namespaceExists = false;
    try {
      await this.api.lookupNamespace(namespace);
      namespaceExists = true;
      this.logger.debug("Namespace already exists, skipping create", { namespace });
    } catch (lookupErr) {
      const code = lookupErr instanceof DeDiClientError ? lookupErr.statusCode : 0;
      // 404 (not found) is the expected "needs create" path. Any other
      // error is unexpected and should propagate — we don't want to fall
      // back to create on a transient lookup failure because that's exactly
      // how duplicates were getting created before.
      if (code !== 404) {
        this.logger.error("Namespace lookup failed unexpectedly", {
          namespace,
          code,
          error: lookupErr instanceof Error ? lookupErr.message : String(lookupErr),
        });
        throw lookupErr;
      }
    }

    if (!namespaceExists) {
      try {
        const nsResult = await this.api.createNamespace(namespace, "OpenCred namespace");
        this.logger.debug("Namespace created", {
          namespace,
          result: JSON.stringify(nsResult).slice(0, 200),
        });
      } catch (nsErr) {
        const code = nsErr instanceof DeDiClientError ? nsErr.statusCode : 0;
        // Belt-and-braces: even after lookup-first, a concurrent create from
        // another client could race in. Accept both HTTP 409 and a body code
        // matching "NAMESPACE_EXISTS" / "ALREADY_EXISTS" as "someone else
        // got there first" — same outcome as if we'd seen the lookup hit.
        if (code === 409 || isAlreadyExistsBody(nsErr)) {
          this.logger.debug("Namespace already existed (race after lookup)", { namespace });
        } else {
          this.logger.error("Namespace creation failed", {
            namespace,
            code,
            error: nsErr instanceof Error ? nsErr.message : String(nsErr),
          });
          throw nsErr;
        }
      }
    }

    await Promise.all([
      // REVOCATION_REGISTRY uses DeDi's canonical "Revoke" tag (schema
      // https://dedi.global/revoke.json). DeDi enforces the
      // `{ revoked_id, reason? }` shape server-side via the tag, so we
      // pass no custom schema body. Record existence ⇒ revoked. The tag
      // string is case-sensitive: dedi.global/schemas exposes "Revoke"
      // (capital R) — lowercase is rejected with 400 (see #609).
      ignoreConflict(() => this.api.createRegistry(namespace, REVOCATION_REGISTRY, {}, "Revoke")),
      // Per-key registry — one record per signing key, the source of truth
      // for "is this key live?". See docs/decisions/dedi-key-registry-redesign.md.
      ignoreConflict(() =>
        this.api.createRegistry(namespace, OPENCRED_KEY_REGISTRY, {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          description: "OpenCred per-key registry (status + public key material)",
          properties: {
            keyId: { type: "string", pattern: "^did:" },
            controllerDid: { type: "string", pattern: "^did:" },
            algorithm: { type: "string" },
            publicKeyJwk: { type: "object", description: "Public key material as a JWK." },
            purpose: { type: "array", items: { type: "string" } },
            status: { type: "string", enum: ["active", "rotated", "revoked"] },
          },
          required: ["keyId", "controllerDid", "algorithm", "publicKeyJwk", "purpose", "status"],
          additionalProperties: false,
        }),
      ),
      // DeDi-hosted DID documents — optional per issuer; backs the did:web
      // fallback resolver and lets a no-webserver issuer host did.json here.
      ignoreConflict(() =>
        this.api.createRegistry(namespace, DID_DOCUMENTS_REGISTRY, {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          description: "OpenCred DeDi-hosted DID documents",
          properties: {
            did: { type: "string", pattern: "^did:" },
            document: { type: "object", description: "W3C DID Document (did.json)." },
          },
          required: ["did", "document"],
          additionalProperties: false,
        }),
      ),
      ignoreConflict(() =>
        this.api.createRegistry(namespace, SCHEMA_REGISTRY, {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          description: "OpenCred credential schema catalog",
          properties: {
            schemaId: { type: "string" },
            version: { type: "string" },
            schema: { type: "object" },
            checksum: { type: "string" },
            publishedAt: { type: "string" },
          },
          required: ["schemaId", "version", "schema"],
        }),
      ),
      // CONTEXT_REGISTRY stores JSON-LD context documents, which are dynamic
      // and don't fit a fixed schema. DeDi has no no-schema "custom" tag
      // (verified against api.dedi.global, #609), so we pass a permissive
      // inline schema: only `@context` is required, anything else passes.
      ignoreConflict(() =>
        this.api.createRegistry(namespace, CONTEXT_REGISTRY, {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          description: "OpenCred JSON-LD context registry",
          properties: {
            "@context": {},
          },
          required: ["@context"],
          additionalProperties: true,
        }),
      ),
    ]);
  }

  private resolveNamespace(explicit?: string): string {
    const ns = explicit ?? this.defaultNamespace;
    if (!ns) {
      throw new DeDiClientError("No namespace provided and no defaultNamespace configured", 400);
    }
    return ns;
  }
}

async function ignoreConflict(fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (error) {
    if (error instanceof DeDiClientError && error.statusCode === 409) {
      return; // Already exists — idempotent success
    }
    if (isAlreadyExistsBody(error)) {
      // DeDi sometimes returns 400 with a body code like `NAMESPACE_EXISTS`
      // or `REGISTRY_EXISTS` rather than the more conventional 409. Treat
      // those as benign "already exists" the same way. See #546.
      return;
    }
    throw error;
  }
}

const ALREADY_EXISTS_BODY_CODE_PATTERN = /^(.*_)?(ALREADY_EXISTS|EXISTS)$/i;

/**
 * Returns `true` if the error's response body advertises an "already exists"
 * condition via a stable code field. Matches both top-level `code` and
 * `error.code` patterns and the common substring forms (`NAMESPACE_EXISTS`,
 * `REGISTRY_ALREADY_EXISTS`, `RESOURCE_EXISTS`, etc.).
 */
function isAlreadyExistsBody(error: unknown): boolean {
  if (!(error instanceof DeDiClientError) || error.responseBody == null) {
    return false;
  }
  const body = error.responseBody;
  if (typeof body !== "object") return false;
  const rec = body as Record<string, unknown>;
  const candidates: unknown[] = [
    rec["code"],
    rec["error_code"],
    rec["errorCode"],
    (rec["error"] as { code?: unknown } | undefined)?.code,
  ];
  return candidates.some((c) => typeof c === "string" && ALREADY_EXISTS_BODY_CODE_PATTERN.test(c));
}

/**
 * Matches the duplicate-record-name signal that DeDi's
 * `save-record-as-draft` returns when a publish collides with an existing
 * `record_name`. Observed wire shape on `api.dedi.global`:
 *
 *   {
 *     "message": "duplicate record name",
 *     "data": "Record with the same name already exists in the registry - vc-revocation-registry"
 *   }
 *
 * Distinct from {@link isAlreadyExistsBody} (which keys off structured `code`
 * fields used by namespace/registry creation). This helper inspects the
 * human-readable `message`/`data` text — robust against minor wording drift
 * by checking both fields and JSON-stringified fallback. Used by
 * `publishRevocationHash`, `publishKey`, and `publishDidDocument` to translate the bare 409 from
 * `publishRecord` into a `DeDiRecordExistsError` with an actionable hint.
 */
const DUPLICATE_RECORD_TEXT_PATTERNS: readonly RegExp[] = [
  /duplicate.*record/i,
  /record.*already.*exists/i,
];

function isDuplicateRecordBody(error: unknown): boolean {
  if (!(error instanceof DeDiClientError) || error.statusCode !== 409) {
    return false;
  }
  const body = error.responseBody;
  if (body == null) return false;
  const candidates: string[] = [];
  if (typeof body === "string") {
    candidates.push(body);
  } else if (typeof body === "object") {
    const rec = body as Record<string, unknown>;
    if (typeof rec["message"] === "string") candidates.push(rec["message"] as string);
    if (typeof rec["data"] === "string") candidates.push(rec["data"] as string);
    // Last-resort: stringify the whole body so unusual shapes still match.
    try {
      candidates.push(JSON.stringify(body));
    } catch {
      // Body has cycles / non-serializable members — the string fields above
      // are the only signal we can trust.
    }
  }
  return candidates.some((text) =>
    DUPLICATE_RECORD_TEXT_PATTERNS.some((pattern) => pattern.test(text)),
  );
}
