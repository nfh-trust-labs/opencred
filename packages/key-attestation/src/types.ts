/**
 * Key Attestation VC types.
 *
 * A Key Attestation VC is a W3C Verifiable Credential that endorses
 * an issuer's public key after identity verification (e.g., domain ownership).
 * It is signed by OpenCred's own DSC key.
 */

import type { Proof, VerifiableCredential } from "@opencred/vc-core";

/** The OpenCred Key Attestation v1 context URI. */
export const OPENCRED_KEY_ATTESTATION_V1_CONTEXT =
  "https://opencred.dev/ns/key-attestation/v1";

/** JWK public key representation (Node.js-compatible). */
export interface PublicKeyJwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  [key: string]: unknown;
}

/** Verification methods for domain ownership. */
export type IdentityVerificationMethod = "dns-txt" | "http-challenge";

/** Identity verification details embedded in the attestation. */
export interface IdentityVerification {
  method: IdentityVerificationMethod;
  verifiedDomain: string;
  verifiedAt: string;
  challengeId: string;
}

/** The credentialSubject of a Key Attestation VC. */
export interface KeyAttestationSubject {
  id: string;
  keyJwk: PublicKeyJwk;
  keyFingerprint: string;
  keyAlgorithm: string;
  verificationMethodId: string;
  identityVerification: IdentityVerification;
  organizationName: string;
  [key: string]: unknown;
}

/** A Key Attestation Verifiable Credential. */
export interface KeyAttestationCredential extends VerifiableCredential {
  type: ["VerifiableCredential", "KeyAttestationCredential"];
  credentialSubject: KeyAttestationSubject;
}

/** An unsigned Key Attestation VC (before proof is attached). */
export interface UnsignedKeyAttestationCredential {
  "@context": string[];
  id: string;
  type: ["VerifiableCredential", "KeyAttestationCredential"];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: KeyAttestationSubject;
}

/** Parameters for creating a Key Attestation VC. */
export interface CreateKeyAttestationParams {
  /** OpenCred's DID (the attestation issuer). */
  opencredDid: string;
  /** The issuer's DID (the subject being attested). */
  issuerDid: string;
  /** The issuer's public key in JWK format. */
  issuerKeyJwk: PublicKeyJwk;
  /** SHA-256 fingerprint of the issuer's public key. */
  keyFingerprint: string;
  /** The key algorithm (e.g., "P-256"). */
  keyAlgorithm: string;
  /** The full verification method ID for the issuer's key. */
  verificationMethodId: string;
  /** Identity verification details. */
  identityVerification: IdentityVerification;
  /** The organization name of the issuer. */
  organizationName: string;
  /** Optional: validFrom (defaults to now). */
  validFrom?: string;
  /** Optional: validUntil (defaults to 1 year from now). */
  validUntil?: string;
}

/** Result of validating a Key Attestation VC. */
export interface KeyAttestationValidationResult {
  valid: boolean;
  errors: string[];
}

/** Options for validating a Key Attestation VC. */
export interface ValidateKeyAttestationOptions {
  /** The time at which to validate (defaults to now). */
  now?: Date;
  /** The signing key to check binding against. */
  signingKeyFingerprint?: string;
  /** The signing key's verification method ID. */
  signingVerificationMethodId?: string;
}

/** Extended proof that includes an embedded Key Attestation VC. */
export interface AttestationProof extends Proof {
  keyAttestationCredential?: KeyAttestationCredential;
  keyAttestationUrl?: string;
}
