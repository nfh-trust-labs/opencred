import type { DeDiApiClientConfig } from "../api/api-client.js";

export interface DeDiClientConfig extends DeDiApiClientConfig {
  defaultNamespace?: string;
}

export type RevocationHashRecord =
  | { hash: string; revoked: false }
  | { hash: string; revoked: true; revokedAt: string };

export interface DelegationRecord {
  id: string;
  issuerDid: string;
  delegateDid: string;
  scope: { credentialTypes: string[]; namespaces: string[] };
  validFrom: string;
  validUntil: string;
  certificate: unknown;
}

export interface DIDRecord {
  did: string;
  document: unknown;
  resolvedAt: string;
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
