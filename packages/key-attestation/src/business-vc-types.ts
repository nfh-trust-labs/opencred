/**
 * Types for business VC identity verification.
 *
 * Used when OpenCred-Attested issuers (User Type 3) prove their identity
 * via an existing W3C Verifiable Credential (e.g., business registration,
 * LEI, or commercial register credential).
 */

import type { CredentialVerificationResult } from "@opencred/verification";

/** Normalized identity extracted from a business VC's credentialSubject. */
export interface BusinessIdentity {
  /** The organization's primary name. */
  organizationName: string;
  /** Legal or registered name, if distinct from organizationName. */
  legalName?: string;
  /** Official registration number (company registry, LEI, etc.). */
  registrationNumber?: string;
  /** ISO 3166-1 alpha-2 country code of registration. */
  country?: string;
  /** A domain associated with the organization. */
  domain?: string;
  /** The id of the credential that was verified to produce this identity. */
  sourceCredentialId?: string;
  /** ISO 8601 timestamp of when the verification occurred. */
  verifiedAt: string;
}

/** Result of verifying a business VC for identity proof. */
export interface BusinessVcVerificationResult {
  /** Whether the business VC was successfully verified and identity extracted. */
  verified: boolean;
  /** Normalized identity, present only when verified is true. */
  identity?: BusinessIdentity;
  /** The underlying credential verification result from the verification engine. */
  verificationResult?: CredentialVerificationResult;
  /** Human-readable error message when verified is false. */
  error?: string;
}
