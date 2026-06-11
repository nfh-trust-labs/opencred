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

// ---------------------------------------------------------------------------
// OpenCred schema library — context URIs
// ---------------------------------------------------------------------------
//
// IMPORTANT: The URLs below for OpenCred-defined credentials embed the current
// `opencred-vc-schemas` commit SHA pinned in
// `packages/schema-engine/scripts/schema-sources.json`. When that SHA is
// bumped, `OPENCRED_SCHEMAS_SHA` below MUST be regenerated to match so the
// BUNDLED_CONTEXTS map in `document-loader.ts` resolves the URLs that end up
// in issued credentials. Stream B's `fetch-and-embed-schemas.mjs` writes the
// raw context JSON files into `packages/vc-core/src/contexts/external/` but
// does not update this constant. Tracked as a follow-up to auto-generate URL
// constants from the manifest so this stays in sync mechanically.
//
// Referenced upstream contexts (Open Badges, Traceability) use stable public
// URLs that do not depend on the schema-sources pin.

/** W3C CCG Traceability Vocabulary v1 — shared by all 21 `traceability/*` credentials. */
export const TRACEABILITY_V1_CONTEXT = "https://w3id.org/traceability/v1";

/** 1EdTech Open Badges 3.0.3 context (referenced upstream). */
export const OPEN_BADGES_V3_CONTEXT = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json";

/**
 * `opencred-vc-schemas` commit SHA that OpenCred-defined context URLs are
 * pinned to. Must match `commit` in
 * `packages/schema-engine/scripts/schema-sources.json`.
 */
const OPENCRED_SCHEMAS_SHA = "ed460795866ce51aebf92e9fccc5f30ff0482dcb";
const OPENCRED_SCHEMAS_BASE = `https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/${OPENCRED_SCHEMAS_SHA}/schemas`;

export const OPENCRED_ELECTRICITY_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/electricity/v1/context.jsonld`;
export const OPENCRED_IMMUNIZATION_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/immunization/v1/context.jsonld`;
export const OPENCRED_PRESCRIPTION_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/prescription/v1/context.jsonld`;
export const OPENCRED_TEST_RESULT_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/test-result/v1/context.jsonld`;
export const OPENCRED_INSURANCE_POLICY_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/insurance-policy/v1/context.jsonld`;
export const OPENCRED_FUNCTIONAL_IDENTITY_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/functional-identity/v1/context.jsonld`;
export const OPENCRED_EMPLOYMENT_OFFER_LETTER_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/employment-offer-letter/v1/context.jsonld`;
export const OPENCRED_BUSINESS_ENTITY_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/business-entity/v1/context.jsonld`;
