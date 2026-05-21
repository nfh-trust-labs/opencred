import { DeDiClientError } from "@opencred/shared";
import { DeDiApiClient } from "../api/api-client.js";
import type { DeDiProof } from "../api/types.js";
import type { DeDiLogger } from "../logger.js";
import { noopLogger } from "../logger.js";
import type {
  DeDiClientConfig,
  RevocationHashRecord,
  DIDRecord,
  SchemaRecord,
  ContextRecord,
  PublishResult,
} from "./types.js";
import {
  REVOCATION_REGISTRY,
  PUBLIC_KEY_REGISTRY,
  SCHEMA_REGISTRY,
  CONTEXT_REGISTRY,
  schemaToRecordName,
  contextToRecordName,
} from "./registry-names.js";

/**
 * Validate a DeDi DID record payload against the 3-field schema:
 * `{ did, document?, keyStatus }`.
 *
 * `document` is optional — did:key records omit it because the verifier
 * derives the document from the DID itself. did:web records carry it
 * (DeDi caches the domain-hosted doc). When present it must be an
 * object; presence-without-shape is the only structural check we do
 * here, the downstream verifier validates the DID-Document contract.
 *
 * `keyStatus` is a strict enum — anything other than `"current"` or
 * `"rotated"` is treated as a server-side bug (502) because the field
 * is what drives the verifier's rotation badge.
 */
function assertDIDRecordShape(detail: unknown): asserts detail is DIDRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("DID record detail is missing or not an object", 502);
  }
  const rec = detail as Record<string, unknown>;
  if (typeof rec["did"] !== "string") {
    throw new DeDiClientError("DID record detail missing required field: did", 502);
  }
  if (rec["keyStatus"] !== "current" && rec["keyStatus"] !== "rotated") {
    throw new DeDiClientError(
      "DID record detail field 'keyStatus' must be 'current' or 'rotated'",
      502,
    );
  }
  if ("document" in rec && (rec["document"] == null || typeof rec["document"] !== "object")) {
    throw new DeDiClientError(
      "DID record detail field 'document' must be an object when present",
      502,
    );
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
    const response = await this.api.publishRecord(ns, REVOCATION_REGISTRY, hash, detailsToPublish);
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
   * Publish a DID document to the DeDi public-key registry.
   *
   * Payload shape: `{ did, document?, keyStatus: "current" }`.
   *
   * - For `did:key`, `document` is omitted regardless of whether the
   *   caller passes one — the verifier derives the document from the DID
   *   via the canonical did:key resolution algorithm, so caching the
   *   document in DeDi adds bytes without information.
   * - For `did:web`, `document` is REQUIRED — the whole point of putting
   *   a did:web in DeDi is to act as a cache of the domain-hosted
   *   `.well-known/did.json`. Calling `publishDID` for a did:web without
   *   a document is a programming error; throws a 400.
   * - For other DID methods, `document` is included if the caller
   *   supplied an object; otherwise omitted.
   *
   * Newly-published records always carry `keyStatus: "current"`. Flip to
   * `"rotated"` later by calling `markDIDRotated`.
   */
  async publishDID(did: string, document: unknown, namespace?: string): Promise<PublishResult> {
    const ns = this.resolveNamespace(namespace);
    const recordName = didToRecordName(did);
    const isDidKey = did.startsWith("did:key:");
    const isDidWeb = did.startsWith("did:web:");

    if (isDidWeb && (document == null || typeof document !== "object")) {
      throw new DeDiClientError("publishDID: did:web records require a DID Document", 400);
    }

    const detail: { did: string; document?: Record<string, unknown>; keyStatus: "current" } = {
      did,
      keyStatus: "current",
    };
    if (!isDidKey && document != null && typeof document === "object") {
      detail.document = document as Record<string, unknown>;
    }

    await this.api.publishRecord(ns, PUBLIC_KEY_REGISTRY, recordName, detail);
    return { published: true, recordName, namespace: ns };
  }

  async resolveDID(did: string, namespace?: string): Promise<DIDRecord> {
    const ns = this.resolveNamespace(namespace);
    const recordName = didToRecordName(did);
    const response = await this.api.lookupRecord(ns, PUBLIC_KEY_REGISTRY, recordName);
    assertDeDiRecordShape(response, "lookupRecord");
    const details = response.data.details;
    assertDIDRecordShape(details);
    const proof = extractProof(response.data);
    return proof ? { ...details, proof } : details;
  }

  /**
   * Flip a published DID's `keyStatus` from `"current"` to `"rotated"`.
   *
   * Called when the issuer rotates to a new key — old credentials remain
   * cryptographically valid against the prior key, but verifier UIs can
   * surface a "key rotated" badge so consumers know to expect a different
   * DID on fresh credentials going forward.
   *
   * The DeDi `update-record` endpoint replaces `details` wholesale, so we
   * read-merge-write: look up the existing record first to preserve
   * `did` and (for did:web) `document`, then send the merged payload back
   * with `keyStatus` flipped.
   *
   * Concurrency story: DeDi's `update-record` has no `If-Match` /
   * `expected_version` parameter, so the naïve read-merge-write would race
   * if two desktops rotated the same DID simultaneously. This is safe
   * today because of two structural facts:
   *   1. The flip is monotone — `current` → `rotated`, never reversed.
   *   2. `did` is the record key (immutable) and `document` is written
   *      only by `publishDID`, not mutated here — so concurrent calls
   *      send identical payloads.
   * Concurrent callers therefore converge to the same state, and the
   * idempotent fast-path below short-circuits any caller whose read sees
   * the record already rotated. Extending `DIDRecord` with a non-monotone
   * field (e.g. `rotatedAt`, `supersededBy`, multi-key state) would break
   * this property — see `DIDRecord` in `./types.ts` before changing the
   * shape.
   *
   * Throws if the record isn't already published. Callers in
   * fire-and-forget paths (e.g. `handleKeyGenerate`) wrap this in
   * `try/catch` to keep a DeDi outage from breaking local key generation.
   */
  async markDIDRotated(did: string, namespace?: string): Promise<void> {
    const ns = this.resolveNamespace(namespace);
    const recordName = didToRecordName(did);
    const existing = await this.resolveDID(did, ns);
    if (existing.keyStatus === "rotated") {
      this.logger.info("DID already marked as rotated; skipping update-record", {
        did,
        namespace: ns,
      });
      return;
    }
    const updatedDetails: DIDRecord = {
      did: existing.did,
      keyStatus: "rotated",
      ...(existing.document !== undefined ? { document: existing.document } : {}),
    };
    await this.api.updateRecord(ns, PUBLIC_KEY_REGISTRY, recordName, updatedDetails);
    this.logger.info("DID marked as rotated in DeDi", { did, namespace: ns });
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
      ignoreConflict(() =>
        this.api.createRegistry(namespace, PUBLIC_KEY_REGISTRY, {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          description: "OpenCred DID Document registry",
          properties: {
            did: { type: "string", pattern: "^did:" },
            document: {
              type: "object",
              description: "W3C DID Document. Omit for did:key — verifier derives from DID.",
            },
            keyStatus: { type: "string", enum: ["current", "rotated"] },
          },
          required: ["did", "keyStatus"],
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

function didToRecordName(did: string): string {
  // Replace characters that aren't safe for DeDi record names
  return did.replace(/:/g, "-");
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
