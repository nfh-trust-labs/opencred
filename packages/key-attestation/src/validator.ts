/**
 * Key Attestation VC validator.
 *
 * Validates the structure, temporal bounds, and key-binding
 * of a Key Attestation VC.
 */

import {
  OPENCRED_KEY_ATTESTATION_V1_CONTEXT,
  type KeyAttestationCredential,
  type KeyAttestationValidationResult,
  type ValidateKeyAttestationOptions,
} from "./types.js";

/**
 * Validate a Key Attestation VC for structural correctness,
 * temporal validity, and optionally key binding.
 *
 * This does NOT verify the cryptographic proof — that is handled
 * by the verification package. This validates the attestation-specific
 * semantics.
 */
export function validateKeyAttestation(
  attestation: unknown,
  options: ValidateKeyAttestationOptions = {},
): KeyAttestationValidationResult {
  const errors: string[] = [];

  // Structural validation
  if (!attestation || typeof attestation !== "object") {
    return { valid: false, errors: ["Attestation must be a non-null object"] };
  }

  const vc = attestation as Record<string, unknown>;

  // Context check
  const contexts = vc["@context"];
  if (!Array.isArray(contexts)) {
    errors.push("@context must be an array");
  } else if (!contexts.includes(OPENCRED_KEY_ATTESTATION_V1_CONTEXT)) {
    errors.push(
      `@context must include ${OPENCRED_KEY_ATTESTATION_V1_CONTEXT}`,
    );
  }

  // Type check
  const types = vc["type"];
  if (!Array.isArray(types)) {
    errors.push("type must be an array");
  } else {
    if (!types.includes("VerifiableCredential")) {
      errors.push("type must include 'VerifiableCredential'");
    }
    if (!types.includes("KeyAttestationCredential")) {
      errors.push("type must include 'KeyAttestationCredential'");
    }
  }

  // Issuer check
  if (!vc["issuer"] || typeof vc["issuer"] !== "string") {
    errors.push("issuer must be a DID string");
  }

  // Credential subject
  const subject = vc["credentialSubject"] as Record<string, unknown> | undefined;
  if (!subject || typeof subject !== "object") {
    errors.push("credentialSubject is required");
  } else {
    if (!subject["id"] || typeof subject["id"] !== "string") {
      errors.push("credentialSubject.id is required");
    }
    if (!subject["keyJwk"] || typeof subject["keyJwk"] !== "object") {
      errors.push("credentialSubject.keyJwk is required");
    }
    if (!subject["keyFingerprint"] || typeof subject["keyFingerprint"] !== "string") {
      errors.push("credentialSubject.keyFingerprint is required");
    }
    if (!subject["keyAlgorithm"] || typeof subject["keyAlgorithm"] !== "string") {
      errors.push("credentialSubject.keyAlgorithm is required");
    }
    if (!subject["verificationMethodId"] || typeof subject["verificationMethodId"] !== "string") {
      errors.push("credentialSubject.verificationMethodId is required");
    }
    if (!subject["organizationName"] || typeof subject["organizationName"] !== "string") {
      errors.push("credentialSubject.organizationName is required");
    }

    // Identity verification sub-object
    const iv = subject["identityVerification"] as Record<string, unknown> | undefined;
    if (!iv || typeof iv !== "object") {
      errors.push("credentialSubject.identityVerification is required");
    } else {
      if (!iv["method"] || typeof iv["method"] !== "string") {
        errors.push("identityVerification.method is required");
      }
      if (!iv["verifiedDomain"] || typeof iv["verifiedDomain"] !== "string") {
        errors.push("identityVerification.verifiedDomain is required");
      }
      if (!iv["verifiedAt"] || typeof iv["verifiedAt"] !== "string") {
        errors.push("identityVerification.verifiedAt is required");
      }
      if (iv["method"] === "business-vc" && (!iv["sourceCredentialId"] || typeof iv["sourceCredentialId"] !== "string")) {
        errors.push("identityVerification.sourceCredentialId is required when method is business-vc");
      }
    }
  }

  // Temporal validation
  const validFrom = vc["validFrom"] as string | undefined;
  const validUntil = vc["validUntil"] as string | undefined;

  if (!validFrom) {
    errors.push("validFrom is required");
  }

  const now = options.now ?? new Date();

  if (validFrom) {
    const from = new Date(validFrom);
    if (isNaN(from.getTime())) {
      errors.push("validFrom is not a valid date");
    } else if (from > now) {
      errors.push("Attestation is not yet valid (validFrom is in the future)");
    }
  }

  if (validUntil) {
    const until = new Date(validUntil);
    if (isNaN(until.getTime())) {
      errors.push("validUntil is not a valid date");
    } else if (until <= now) {
      errors.push("Attestation has expired (validUntil is in the past)");
    }
  }

  // Key binding check (optional — only if signingKeyFingerprint provided)
  if (options.signingKeyFingerprint && subject) {
    const attestedFingerprint = subject["keyFingerprint"] as string | undefined;
    if (attestedFingerprint && attestedFingerprint !== options.signingKeyFingerprint) {
      errors.push(
        `Key binding mismatch: attested fingerprint '${attestedFingerprint}' ` +
        `does not match signing key fingerprint '${options.signingKeyFingerprint}'`,
      );
    }
  }

  // Verification method ID binding check (optional)
  if (options.signingVerificationMethodId && subject) {
    const attestedVmId = subject["verificationMethodId"] as string | undefined;
    if (attestedVmId && attestedVmId !== options.signingVerificationMethodId) {
      // Also check base DID match
      const attestedBase = attestedVmId.split("#")[0];
      const signingBase = options.signingVerificationMethodId.split("#")[0];
      if (attestedBase !== signingBase) {
        errors.push(
          `Verification method mismatch: attested '${attestedVmId}' ` +
          `does not match signing key '${options.signingVerificationMethodId}'`,
        );
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Type guard: check if a credential is a KeyAttestationCredential.
 */
export function isKeyAttestationCredential(
  credential: unknown,
): credential is KeyAttestationCredential {
  if (!credential || typeof credential !== "object") return false;
  const vc = credential as Record<string, unknown>;
  const types = vc["type"];
  return Array.isArray(types) && types.includes("KeyAttestationCredential");
}
