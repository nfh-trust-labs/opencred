/**
 * Key Attestation VC builder.
 *
 * Constructs unsigned Key Attestation VCs that OpenCred signs
 * with its own DSC key to endorse an issuer's public key.
 */

import { randomUUID } from "node:crypto";
import { AttestationError } from "@opencred/shared";
import { W3C_CREDENTIALS_V2_CONTEXT, DATA_INTEGRITY_V1_CONTEXT } from "@opencred/vc-core";
import {
  OPENCRED_KEY_ATTESTATION_V1_CONTEXT,
  type CreateKeyAttestationParams,
  type UnsignedKeyAttestationCredential,
} from "./types.js";

/**
 * Create an unsigned Key Attestation VC.
 *
 * The caller is responsible for signing this with OpenCred's DSC key
 * using the appropriate proof mechanism.
 */
export function createKeyAttestationVC(
  params: CreateKeyAttestationParams,
): UnsignedKeyAttestationCredential {
  validateParams(params);

  const now = new Date();
  const oneYearFromNow = new Date(now);
  oneYearFromNow.setFullYear(oneYearFromNow.getFullYear() + 1);

  const validFrom = params.validFrom ?? now.toISOString();
  const validUntil = params.validUntil ?? oneYearFromNow.toISOString();

  return {
    "@context": [
      W3C_CREDENTIALS_V2_CONTEXT,
      DATA_INTEGRITY_V1_CONTEXT,
      OPENCRED_KEY_ATTESTATION_V1_CONTEXT,
    ],
    id: `urn:uuid:${randomUUID()}`,
    type: ["VerifiableCredential", "KeyAttestationCredential"],
    issuer: params.opencredDid,
    validFrom,
    validUntil,
    credentialSubject: {
      id: params.issuerDid,
      keyJwk: params.issuerKeyJwk,
      keyFingerprint: params.keyFingerprint,
      keyAlgorithm: params.keyAlgorithm,
      verificationMethodId: params.verificationMethodId,
      identityVerification: params.identityVerification,
      organizationName: params.organizationName,
    },
  };
}

function validateParams(params: CreateKeyAttestationParams): void {
  if (!params.opencredDid || !params.opencredDid.startsWith("did:")) {
    throw new AttestationError("opencredDid must be a valid DID");
  }
  if (!params.issuerDid || !params.issuerDid.startsWith("did:")) {
    throw new AttestationError("issuerDid must be a valid DID");
  }
  if (!params.issuerKeyJwk || !params.issuerKeyJwk.kty) {
    throw new AttestationError("issuerKeyJwk must be a valid JWK with kty");
  }
  if (!params.keyFingerprint) {
    throw new AttestationError("keyFingerprint is required");
  }
  if (!params.keyAlgorithm) {
    throw new AttestationError("keyAlgorithm is required");
  }
  if (!params.verificationMethodId) {
    throw new AttestationError("verificationMethodId is required");
  }
  if (!params.identityVerification) {
    throw new AttestationError("identityVerification is required");
  }
  if (!params.identityVerification.method) {
    throw new AttestationError("identityVerification.method is required");
  }
  if (!params.identityVerification.verifiedDomain) {
    throw new AttestationError("identityVerification.verifiedDomain is required");
  }
  if (!params.identityVerification.verifiedAt) {
    throw new AttestationError("identityVerification.verifiedAt is required");
  }
  if (!params.identityVerification.challengeId) {
    throw new AttestationError("identityVerification.challengeId is required");
  }
  if (!params.organizationName) {
    throw new AttestationError("organizationName is required");
  }

  // Validate dates if provided
  if (params.validFrom && isNaN(new Date(params.validFrom).getTime())) {
    throw new AttestationError("validFrom must be a valid ISO 8601 date");
  }
  if (params.validUntil && isNaN(new Date(params.validUntil).getTime())) {
    throw new AttestationError("validUntil must be a valid ISO 8601 date");
  }
  if (params.validFrom && params.validUntil) {
    if (new Date(params.validFrom) >= new Date(params.validUntil)) {
      throw new AttestationError("validFrom must be before validUntil");
    }
  }
}
