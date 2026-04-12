import { DeDiClientError } from "@opencred/shared";
import { DeDiApiClient } from "../api/api-client.js";
import type { DeDiLogger } from "../logger.js";
import { noopLogger } from "../logger.js";
import type {
  DeDiClientConfig,
  RevocationHashRecord,
  DelegationRecord,
  DIDRecord,
  SchemaRecord,
  ContextRecord,
  PublishResult,
} from "./types.js";
import {
  REVOCATION_REGISTRY,
  DELEGATION_REGISTRY,
  PUBLIC_KEY_REGISTRY,
  SCHEMA_REGISTRY,
  CONTEXT_REGISTRY,
  schemaToRecordName,
  contextToRecordName,
} from "./registry-names.js";

const DELEGATION_DETAIL_KEYS = [
  "id",
  "issuerDid",
  "delegateDid",
  "scope",
  "validFrom",
  "validUntil",
] as const;

function validateDelegation(delegation: DelegationRecord): void {
  if (delegation.scope.credentialTypes.length === 0 && delegation.scope.namespaces.length === 0) {
    throw new DeDiClientError("Delegation scope must not be empty", 400);
  }
  const from = new Date(delegation.validFrom);
  const until = new Date(delegation.validUntil);
  if (isNaN(from.getTime())) {
    throw new DeDiClientError("validFrom is not a valid date", 400);
  }
  if (isNaN(until.getTime())) {
    throw new DeDiClientError("validUntil is not a valid date", 400);
  }
  if (from >= until) {
    throw new DeDiClientError("validFrom must precede validUntil", 400);
  }
}

function assertDelegationShape(detail: unknown): asserts detail is DelegationRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("Delegation detail is missing or not an object", 502);
  }
  const rec = detail as Record<string, unknown>;
  for (const key of DELEGATION_DETAIL_KEYS) {
    if (!(key in rec)) {
      throw new DeDiClientError(`Delegation detail missing required field: ${key}`, 502);
    }
  }
  if (rec["scope"] == null || typeof rec["scope"] !== "object" || Array.isArray(rec["scope"])) {
    throw new DeDiClientError(
      "Delegation detail field 'scope' must be an object with credentialTypes and namespaces",
      502,
    );
  }
  const scope = rec["scope"] as Record<string, unknown>;
  if (!Array.isArray(scope["credentialTypes"])) {
    throw new DeDiClientError("Delegation scope field 'credentialTypes' must be an array", 502);
  }
  if (!scope["credentialTypes"].every((v: unknown) => typeof v === "string")) {
    throw new DeDiClientError(
      "Delegation scope field 'credentialTypes' must contain only strings",
      502,
    );
  }
  if (!Array.isArray(scope["namespaces"])) {
    throw new DeDiClientError("Delegation scope field 'namespaces' must be an array", 502);
  }
  if (!scope["namespaces"].every((v: unknown) => typeof v === "string")) {
    throw new DeDiClientError("Delegation scope field 'namespaces' must contain only strings", 502);
  }
}

function assertRevocationHashShape(detail: unknown): asserts detail is RevocationHashRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("Revocation hash detail is missing or not an object", 502);
  }
  const rec = detail as Record<string, unknown>;
  if (typeof rec["hash"] !== "string") {
    throw new DeDiClientError("Revocation hash detail missing required field: hash", 502);
  }
  if (typeof rec["revoked"] !== "boolean") {
    throw new DeDiClientError("Revocation hash detail missing required field: revoked", 502);
  }
  if (rec["revoked"] === true && typeof rec["revokedAt"] !== "string") {
    throw new DeDiClientError("Revocation hash detail missing required field: revokedAt", 502);
  }
}

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

function assertDeDiRecordShape(value: unknown, label: string): void {
  if (value == null || typeof value !== "object") {
    throw new DeDiClientError(`DeDi API ${label} response is missing or not an object`, 502);
  }
  const rec = value as Record<string, unknown>;
  if (typeof rec["name"] !== "string") {
    throw new DeDiClientError(`DeDi API ${label} response missing required field: name`, 502);
  }
  if (!("detail" in rec)) {
    throw new DeDiClientError(`DeDi API ${label} response missing required field: detail`, 502);
  }
}

function assertSearchResultShape(value: unknown): void {
  if (value == null || typeof value !== "object") {
    throw new DeDiClientError("DeDi API search response is missing or not an object", 502);
  }
  const rec = value as Record<string, unknown>;
  if (!Array.isArray(rec["records"])) {
    throw new DeDiClientError("DeDi API search response field 'records' must be an array", 502);
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

  async publishRevocationHash(hash: string, namespace?: string): Promise<RevocationHashRecord> {
    const ns = this.resolveNamespace(namespace);
    const revokedAt = new Date().toISOString();
    const record = await this.api.publishRecord(ns, REVOCATION_REGISTRY, hash, {
      hash,
      revoked: true,
      revokedAt,
    });
    assertDeDiRecordShape(record, "publishRecord");
    assertRevocationHashShape(record.detail);
    return record.detail;
  }

  async queryRevocationHash(hash: string, namespace?: string): Promise<RevocationHashRecord> {
    const ns = this.resolveNamespace(namespace);

    const result = await this.api.search(ns, {
      registry_name: REVOCATION_REGISTRY,
      "detail.hash": hash,
    });
    assertSearchResultShape(result);

    if (result.records.length === 0) {
      return { hash, revoked: false as const };
    }

    assertDeDiRecordShape(result.records[0], "search record");
    const detail = result.records[0]!.detail;
    assertRevocationHashShape(detail);
    return detail;
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
    const record = await this.api.lookupRecord(ns, PUBLIC_KEY_REGISTRY, recordName);
    assertDeDiRecordShape(record, "lookupRecord");
    assertDIDRecordShape(record.detail);
    return record.detail;
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
    const record = await this.api.lookupRecord(ns, SCHEMA_REGISTRY, recordName);
    assertDeDiRecordShape(record, "lookupRecord");
    assertSchemaRecordShape(record.detail);
    return record.detail;
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
    const record = await this.api.lookupRecord(ns, CONTEXT_REGISTRY, recordName);
    assertDeDiRecordShape(record, "lookupRecord");
    assertContextRecordShape(record.detail);
    return record.detail;
  }

  async registerDelegation(
    delegation: DelegationRecord,
    namespace?: string,
  ): Promise<DelegationRecord> {
    validateDelegation(delegation);
    const ns = this.resolveNamespace(namespace);
    const record = await this.api.publishRecord(ns, DELEGATION_REGISTRY, delegation.id, delegation);
    assertDeDiRecordShape(record, "publishRecord");
    assertDelegationShape(record.detail);
    return record.detail;
  }

  async resolveDelegation(delegationId: string, namespace?: string): Promise<DelegationRecord> {
    const ns = this.resolveNamespace(namespace);
    const record = await this.api.lookupRecord(ns, DELEGATION_REGISTRY, delegationId);
    assertDeDiRecordShape(record, "lookupRecord");
    assertDelegationShape(record.detail);
    return record.detail;
  }

  async ensureRegistries(namespace: string): Promise<void> {
    try {
      const nsResult = await this.api.createNamespace(namespace, "OpenCred namespace");
      this.logger.debug("Namespace created", {
        namespace,
        result: JSON.stringify(nsResult).slice(0, 200),
      });
    } catch (nsErr) {
      const code = nsErr instanceof DeDiClientError ? nsErr.statusCode : 0;
      this.logger.error("Namespace creation failed", {
        namespace,
        code,
        error: nsErr instanceof Error ? nsErr.message : String(nsErr),
      });
      if (code !== 409) throw nsErr; // Only ignore "already exists"
    }

    await Promise.all([
      ignoreConflict(() =>
        this.api.createRegistry(namespace, REVOCATION_REGISTRY, {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          description: "OpenCred revocation list",
          properties: {
            hash: { type: "string" },
            revoked: { type: "boolean" },
            revokedAt: { type: "string" },
          },
          required: ["hash", "revoked"],
        }),
      ),
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
    throw error;
  }
}
