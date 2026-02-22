export interface DeDiClientConfig {
  baseUrl: string;
  timeoutMs: number;
  maxRetries: number;
  circuitBreakerThreshold: number;
}

export interface RevocationHashRecord {
  hash: string;
  revoked: boolean;
  revokedAt?: string;
}

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

export const enum CircuitBreakerState {
  CLOSED = "CLOSED",
  OPEN = "OPEN",
  HALF_OPEN = "HALF_OPEN",
}
