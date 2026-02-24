import type { KeyObject } from "node:crypto";
import type { ContextEntry, Proof } from "@opencred/vc-core";

/**
 * Delegation certificate JSON-LD structure.
 *
 * A delegation certificate captures the authorisation granted by an issuer
 * (delegator) to OpenCred (delegatee) to sign credentials on the issuer's
 * behalf. The certificate is itself a signed document — the delegator signs
 * it with their authority key (ephemeral, passkey, or DSC), establishing
 * the trust chain: VC signature → OpenCred's key → delegation certificate
 * → issuer's authority.
 *
 * PRD Section 5.3 requirements:
 * - MUST identify the issuer (delegator) by stable identifier
 * - MUST identify the OpenCred signing key(s) (delegatee) by key ID
 * - SHOULD include validity period (validFrom, validUntil)
 * - SHOULD include scope constraints (credential types, namespaces)
 * - MUST be cryptographically signed
 */
export interface DelegationCertificate {
  "@context": ContextEntry[];
  id: string;
  type: ["DelegationCertificate"];
  delegator: Delegator;
  delegatee: Delegatee;
  scope: DelegationScope;
  validFrom: string;
  validUntil: string;
  authorisationPath: AuthorisationPath;
  credentialStatus?: DelegationCredentialStatus;
  proof?: Proof;
}

/**
 * Unsigned delegation certificate — before the delegator signs it.
 */
export type UnsignedDelegationCertificate = Omit<DelegationCertificate, "proof">;

/**
 * The issuer who delegates signing authority to OpenCred.
 * Identified by their stable identifier (domain URL, business ID, or DID).
 */
export interface Delegator {
  /** Stable identifier — domain URL (e.g., "https://example.com") or DID. */
  id: string;
  /** Human-readable name (e.g., from SSL certificate subject). */
  name?: string;
  /** Optional business registration ID. */
  businessId?: string;
}

/**
 * The OpenCred signing key authorised to sign on behalf of the delegator.
 */
export interface Delegatee {
  /** OpenCred's signing key identifier (e.g., "did:key:z6Mk...#z6Mk..."). */
  id: string;
  /** Optional: the public key in multibase encoding for self-contained verification. */
  publicKeyMultibase?: string;
}

/**
 * Scope constraints limiting what the delegatee can sign.
 * Empty arrays mean "no restriction" for that dimension.
 */
export interface DelegationScope {
  /** Allowed credential types (e.g., ["UniversityDegreeCredential"]). Empty = all types allowed. */
  credentialTypes: string[];
  /** Allowed namespaces (e.g., ["education"]). Empty = all namespaces allowed. */
  namespaces: string[];
  /** Maximum number of credentials that may be issued under this delegation. Omit for unlimited. */
  maxIssuanceCount?: number;
}

/**
 * PRD Section 5.3.1 — three paths for delegation authorisation.
 */
export type AuthorisationPath = "ephemeral-keypair" | "passkey" | "dedi-registry";

/**
 * Credential status for delegation revocation tracking via DeDi.
 */
export interface DelegationCredentialStatus {
  /** DeDi delegation status URL. */
  id: string;
  type: "DeDiDelegationStatus";
  statusPurpose: "revocation";
}

/**
 * Current status of a delegation.
 */
export type DelegationStatus = "active" | "expired" | "revoked" | "not-yet-valid";

/**
 * Parameters for creating a new delegation certificate.
 */
export interface CreateDelegationParams {
  delegator: Delegator;
  delegatee: Delegatee;
  scope: DelegationScope;
  validFrom: string;
  validUntil: string;
  authorisationPath: AuthorisationPath;
  /** Optional custom ID. If omitted, a urn:uuid is generated. */
  id?: string;
  /** Optional credential status for revocation. */
  credentialStatus?: DelegationCredentialStatus;
}

/**
 * Result of validating a delegation certificate.
 */
export interface ValidateDelegationResult {
  valid: boolean;
  status: DelegationStatus;
  errors: string[];
}

/**
 * Options for delegation certificate validation.
 */
export interface ValidateDelegationOptions {
  /** The current time to check against. Defaults to Date.now(). */
  now?: Date;
  /** If provided, verify the proof signature using this key. */
  delegatorPublicKey?: KeyObject;
  /** If provided, check that the credential type is within the delegation's scope. */
  credentialType?: string;
  /** If provided, check that the namespace is within the delegation's scope. */
  namespace?: string;
}

/**
 * Options for embedding a delegation reference in a credential.
 */
export interface EmbedDelegationOptions {
  /** Embed the full certificate inline (true) or just a reference URL (false). Default: true. */
  inline?: boolean;
  /** DeDi URL where the delegation is stored (required when inline=false). */
  delegationUrl?: string;
}

/**
 * A verifiable credential with an embedded or referenced delegation certificate.
 * Extends the base VC proof with delegation information.
 */
export interface DelegatedCredentialProof extends Proof {
  delegationCertificate?: DelegationCertificate;
  delegationCertificateUrl?: string;
}

/**
 * Parameters for registering a delegation in DeDi.
 */
export interface RegisterDelegationParams {
  certificate: DelegationCertificate;
}

/**
 * Parameters for resolving a delegation from DeDi.
 */
export interface ResolveDelegationParams {
  delegationId: string;
}

/**
 * Re-export the delegation context URI from vc-core where it's defined
 * alongside the other bundled context URIs.
 */
export { OPENCRED_DELEGATION_V1_CONTEXT as OPENCRED_DELEGATION_CONTEXT } from "@opencred/vc-core";
