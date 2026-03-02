import { DeDiClientError } from "@opencred/shared";
import { DeDiApiClient } from "../api/api-client.js";
import type { DeDiLogger } from "../logger.js";
import { noopLogger } from "../logger.js";
import type {
  DeDiClientConfig,
  RevocationHashRecord,
  DelegationRecord,
  DIDRecord,
} from "./types.js";
import {
  REVOCATION_REGISTRY,
  DELEGATION_REGISTRY,
  PUBLIC_KEY_REGISTRY,
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
  if (
    delegation.scope.credentialTypes.length === 0 &&
    delegation.scope.namespaces.length === 0
  ) {
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

function assertDelegationShape(
  detail: unknown,
): asserts detail is DelegationRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError(
      "Delegation detail is missing or not an object",
      502,
    );
  }
  const rec = detail as Record<string, unknown>;
  for (const key of DELEGATION_DETAIL_KEYS) {
    if (!(key in rec)) {
      throw new DeDiClientError(
        `Delegation detail missing required field: ${key}`,
        502,
      );
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
    throw new DeDiClientError(
      "Delegation scope field 'credentialTypes' must be an array",
      502,
    );
  }
  if (!scope["credentialTypes"].every((v: unknown) => typeof v === "string")) {
    throw new DeDiClientError(
      "Delegation scope field 'credentialTypes' must contain only strings",
      502,
    );
  }
  if (!Array.isArray(scope["namespaces"])) {
    throw new DeDiClientError(
      "Delegation scope field 'namespaces' must be an array",
      502,
    );
  }
  if (!scope["namespaces"].every((v: unknown) => typeof v === "string")) {
    throw new DeDiClientError(
      "Delegation scope field 'namespaces' must contain only strings",
      502,
    );
  }
}

function assertRevocationHashShape(
  detail: unknown,
): asserts detail is RevocationHashRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError(
      "Revocation hash detail is missing or not an object",
      502,
    );
  }
  const rec = detail as Record<string, unknown>;
  if (typeof rec["hash"] !== "string") {
    throw new DeDiClientError(
      "Revocation hash detail missing required field: hash",
      502,
    );
  }
  if (typeof rec["revoked"] !== "boolean") {
    throw new DeDiClientError(
      "Revocation hash detail missing required field: revoked",
      502,
    );
  }
  if (rec["revoked"] === true && typeof rec["revokedAt"] !== "string") {
    throw new DeDiClientError(
      "Revocation hash detail missing required field: revokedAt",
      502,
    );
  }
}

function assertDIDRecordShape(
  detail: unknown,
): asserts detail is DIDRecord {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError(
      "DID record detail is missing or not an object",
      502,
    );
  }
  const rec = detail as Record<string, unknown>;
  if (typeof rec["did"] !== "string") {
    throw new DeDiClientError(
      "DID record detail missing required field: did",
      502,
    );
  }
  if (!("document" in rec)) {
    throw new DeDiClientError(
      "DID record detail missing required field: document",
      502,
    );
  }
  if (typeof rec["resolvedAt"] !== "string") {
    throw new DeDiClientError(
      "DID record detail missing required field: resolvedAt",
      502,
    );
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

  async publishRevocationHash(
    hash: string,
    namespace?: string,
  ): Promise<RevocationHashRecord> {
    const ns = this.resolveNamespace(namespace);
    const revokedAt = new Date().toISOString();
    const record = await this.api.publishRecord(ns, REVOCATION_REGISTRY, hash, {
      hash,
      revoked: true,
      revokedAt,
    });
    assertRevocationHashShape(record.detail);
    return record.detail;
  }

  async queryRevocationHash(
    hash: string,
    namespace?: string,
  ): Promise<RevocationHashRecord> {
    const ns = this.resolveNamespace(namespace);

    const result = await this.api.search(ns, {
      registry_name: REVOCATION_REGISTRY,
      "detail.hash": hash,
    });

    if (result.records.length === 0) {
      return { hash, revoked: false as const };
    }

    const detail = result.records[0]!.detail;
    assertRevocationHashShape(detail);
    return detail;
  }

  async resolveDID(did: string, namespace?: string): Promise<DIDRecord> {
    const ns = this.resolveNamespace(namespace);
    const recordName = didToRecordName(did);
    const record = await this.api.lookupRecord(ns, PUBLIC_KEY_REGISTRY, recordName);
    assertDIDRecordShape(record.detail);
    return record.detail;
  }

  async registerDelegation(
    delegation: DelegationRecord,
    namespace?: string,
  ): Promise<DelegationRecord> {
    validateDelegation(delegation);
    const ns = this.resolveNamespace(namespace);
    const record = await this.api.publishRecord(
      ns,
      DELEGATION_REGISTRY,
      delegation.id,
      delegation,
    );
    assertDelegationShape(record.detail);
    return record.detail;
  }

  async resolveDelegation(
    delegationId: string,
    namespace?: string,
  ): Promise<DelegationRecord> {
    const ns = this.resolveNamespace(namespace);
    const record = await this.api.lookupRecord(
      ns,
      DELEGATION_REGISTRY,
      delegationId,
    );
    assertDelegationShape(record.detail);
    return record.detail;
  }

  async ensureRegistries(namespace: string): Promise<void> {
    await ignoreConflict(() =>
      this.api.createNamespace(namespace, "OpenCred namespace"),
    );

    await Promise.all([
      ignoreConflict(() =>
        this.api.createRegistry(namespace, REVOCATION_REGISTRY, {}, "revoke"),
      ),
      ignoreConflict(() =>
        this.api.createRegistry(namespace, DELEGATION_REGISTRY, {}, "membership"),
      ),
      ignoreConflict(() =>
        this.api.createRegistry(namespace, PUBLIC_KEY_REGISTRY, {}, "public_key"),
      ),
    ]);
  }

  private resolveNamespace(explicit?: string): string {
    const ns = explicit ?? this.defaultNamespace;
    if (!ns) {
      throw new DeDiClientError(
        "No namespace provided and no defaultNamespace configured",
        400,
      );
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
