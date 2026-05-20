import { DeDiClientError } from "@opencred/shared";
import { DeDiApiClient } from "../api/api-client.js";
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

function assertDIDRecordShape(detail: unknown): asserts detail is DIDRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("DID record detail is missing or not an object", 502);
  }
  const rec = detail as Record<string, unknown>;
  if (typeof rec["did"] !== "string") {
    throw new DeDiClientError("DID record detail missing required field: did", 502);
  }
  if (!("document" in rec)) {
    throw new DeDiClientError("DID record detail missing required field: document", 502);
  }
  if (typeof rec["resolvedAt"] !== "string") {
    throw new DeDiClientError("DID record detail missing required field: resolvedAt", 502);
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
 * Validate that a search response matches the real DeDi envelope shape
 * — `{ message, data: DeDiRecord<T>[] }`. The payload lives under
 * `data` as an array of records; pagination is communicated out-of-band
 * by the server.
 */
function assertSearchResultShape(
  value: unknown,
): asserts value is { message: string; data: unknown[] } {
  if (value == null || typeof value !== "object") {
    throw new DeDiClientError("DeDi API search response is missing or not an object", 502);
  }
  const env = value as Record<string, unknown>;
  if (!Array.isArray(env["data"])) {
    throw new DeDiClientError("DeDi API search response field 'data' must be an array", 502);
  }
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
   * Record existence ⇒ revoked (DeDi canonical `revoke` tag semantics).
   * Returns `{ revoked: false }` when no record is found.
   */
  async queryRevocationHash(hash: string, namespace?: string): Promise<RevocationHashRecord> {
    const ns = this.resolveNamespace(namespace);

    const response = await this.api.search(ns, {
      registry_name: REVOCATION_REGISTRY,
      "details.revoked_id": hash,
    });
    assertSearchResultShape(response);

    if (response.data.length === 0) {
      return { revoked: false };
    }

    assertDeDiRecordPayload(response.data[0], "search record");
    // Search payload is a bare DeDiRecord; assertDeDiRecordPayload only
    // narrows the minimum required fields. Cast through the wire shape
    // so we can read the envelope's `updated_at` revocation timestamp.
    const record = response.data[0] as {
      record_name: string;
      details: unknown;
      updated_at?: string;
    };
    const details = record.details as Record<string, unknown> | null | undefined;
    const reason =
      details && typeof details["reason"] === "string" ? (details["reason"] as string) : undefined;
    return {
      revoked: true,
      revokedAt: record.updated_at ?? "",
      ...(reason !== undefined ? { reason } : {}),
    };
  }

  async publishDID(did: string, document: unknown, namespace?: string): Promise<PublishResult> {
    const ns = this.resolveNamespace(namespace);
    const recordName = didToRecordName(did);
    const detail: DIDRecord = {
      did,
      document,
      resolvedAt: new Date().toISOString(),
    };
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
    return details;
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
    return details;
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
      // REVOCATION_REGISTRY uses DeDi's canonical "revoke" tag (schema
      // https://dedi.global/revoke.json). DeDi enforces the
      // `{ revoked_id, reason? }` shape server-side via the tag, so we
      // pass no custom schema body. Record existence ⇒ revoked.
      ignoreConflict(() => this.api.createRegistry(namespace, REVOCATION_REGISTRY, {}, "revoke")),
      ignoreConflict(() =>
        this.api.createRegistry(namespace, PUBLIC_KEY_REGISTRY, {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          description: "OpenCred public key registry",
          properties: {
            did: { type: "string" },
            document: { type: "object" },
            resolvedAt: { type: "string" },
          },
          required: ["did", "document"],
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
      // CONTEXT_REGISTRY uses "custom" tag (no JSON schema) because JSON-LD
      // context documents are dynamic and don't fit a fixed schema.
      ignoreConflict(() => this.api.createRegistry(namespace, CONTEXT_REGISTRY, {}, "custom")),
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
