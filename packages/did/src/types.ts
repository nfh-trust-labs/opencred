export interface JWK {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
  [key: string]: unknown;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: JWK;
  publicKeyMultibase?: string;
}

export interface DIDDocument {
  "@context": string | string[];
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  capabilityInvocation?: (string | VerificationMethod)[];
  capabilityDelegation?: (string | VerificationMethod)[];
}

export interface DIDResolutionResult {
  didDocument: DIDDocument | null;
  didResolutionMetadata: Record<string, unknown>;
  didDocumentMetadata: Record<string, unknown>;
}
