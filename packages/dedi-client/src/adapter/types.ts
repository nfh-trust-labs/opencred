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
  scope: string[];
  validFrom: string;
  validUntil: string;
  certificate: unknown;
}

export interface DIDRecord {
  did: string;
  document: unknown;
  resolvedAt: string;
}
