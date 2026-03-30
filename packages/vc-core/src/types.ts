/**
 * W3C Verifiable Credentials Data Model 2.0 TypeScript types.
 * @see https://www.w3.org/TR/vc-data-model-2.0/
 */

/** JSON-LD context — a single URI string or a context object. */
export type ContextEntry = string | Record<string, unknown>;

/** The issuer of a credential — either a DID string or an object with an `id`. */
export type Issuer = string | IssuerObject;

export interface IssuerObject {
  id: string;
  name?: string;
  [key: string]: unknown;
}

/** A credential subject containing claims about a subject. */
export interface CredentialSubject {
  id?: string;
  [key: string]: unknown;
}

/**
 * Credential status for revocation checking.
 * OpenCred uses type "dedi" with DeDi revocation registries.
 */
export interface CredentialStatus {
  id: string;
  type: string;
  statusPurpose: string;
  statusListCredential?: string;
  [key: string]: unknown;
}

/** A credential schema for validation. */
export interface CredentialSchema {
  id: string;
  type: string;
}

/** Data Integrity proof structure. */
export interface Proof {
  type: string;
  cryptosuite?: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
  [key: string]: unknown;
}

/**
 * W3C Verifiable Credential Data Model 2.0.
 * Represents an unsigned credential (no proof attached).
 */
export interface UnsignedCredential {
  "@context": ContextEntry[];
  id: string;
  type: string[];
  issuer: Issuer;
  validFrom: string;
  validUntil?: string;
  credentialSubject: CredentialSubject;
  credentialStatus?: CredentialStatus;
  credentialSchema?: CredentialSchema;
}

/**
 * W3C Verifiable Credential with attached proof.
 */
export interface VerifiableCredential extends UnsignedCredential {
  proof: Proof;
}

/** The base W3C credentials v2 context URI. */
export const W3C_CREDENTIALS_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";

/** The W3C Data Integrity v1 context URI. */
export const DATA_INTEGRITY_V1_CONTEXT = "https://w3id.org/security/data-integrity/v1";

/** The OpenCred Delegation v1 context URI. */
export const OPENCRED_DELEGATION_V1_CONTEXT = "https://opencred.example/ns/delegation/v1";

/** NFH built-in schema context URIs. */
export const NFH_EDUCATION_V1_CONTEXT = "https://schema.nfh.global/contexts/education/v1";
export const NFH_EMPLOYMENT_V1_CONTEXT = "https://schema.nfh.global/contexts/employment/v1";
export const NFH_IDENTITY_V1_CONTEXT = "https://schema.nfh.global/contexts/identity/v1";
export const NFH_HEALTH_V1_CONTEXT = "https://schema.nfh.global/contexts/health/v1";
export const NFH_BUSINESS_V1_CONTEXT = "https://schema.nfh.global/contexts/business/v1";

