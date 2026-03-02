import { DeDiClientError } from "@opencred/shared";
import { DeDiApiClient } from "../api/api-client.js";
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

export class DeDiClient {
  private readonly api: DeDiApiClient;
  private readonly defaultNamespace?: string;

  constructor(config: DeDiClientConfig) {
    this.api = new DeDiApiClient(config);
    this.defaultNamespace = config.defaultNamespace;
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
    return record.detail as RevocationHashRecord;
  }

  async queryRevocationHash(
    hash: string,
    namespace?: string,
  ): Promise<RevocationHashRecord> {
    const ns = this.resolveNamespace(namespace);

    try {
      const result = await this.api.search(ns, {
        registry_name: REVOCATION_REGISTRY,
        "detail.hash": hash,
      });

      if (result.records.length === 0) {
        return { hash, revoked: false as const };
      }

      return result.records[0]!.detail as RevocationHashRecord;
    } catch (error) {
      // 404 may indicate registry not yet created, namespace missing, or API path mismatch.
      // TODO: Inspect structured error codes from DeDi when available to narrow this.
      if (error instanceof DeDiClientError && error.statusCode === 404) {
        return { hash, revoked: false as const };
      }
      throw error;
    }
  }

  async resolveDID(did: string, namespace?: string): Promise<DIDRecord> {
    const ns = this.resolveNamespace(namespace);
    const recordName = didToRecordName(did);
    const record = await this.api.lookupRecord(ns, PUBLIC_KEY_REGISTRY, recordName);
    return record.detail as DIDRecord;
  }

  async registerDelegation(
    delegation: DelegationRecord,
    namespace?: string,
  ): Promise<DelegationRecord> {
    const ns = this.resolveNamespace(namespace);
    const record = await this.api.publishRecord(
      ns,
      DELEGATION_REGISTRY,
      delegation.id,
      delegation,
    );
    return record.detail as DelegationRecord;
  }

  async resolveDelegation(
    delegationId: string,
    namespace?: string,
  ): Promise<DelegationRecord> {
    const ns = this.resolveNamespace(namespace);
    const record = await this.api.lookupRecord(ns, DELEGATION_REGISTRY, delegationId);
    return record.detail as DelegationRecord;
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
