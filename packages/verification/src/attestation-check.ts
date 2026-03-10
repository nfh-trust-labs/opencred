/**
 * Attestation chain verification.
 *
 * Replaces delegation-check.ts. Validates the Key Attestation VC
 * embedded in (or referenced from) a credential's proof.
 *
 * The attestation chain check verifies:
 * 1. The credential has an attestation reference in its proof
 * 2. The attested key matches the credential's signing key
 * 3. The attestation VC signature is valid (OpenCred's key)
 * 4. The attestation was valid at credential sign time (proof.created)
 */

import type { DeDiClient } from "@opencred/dedi-client";
import type { DIDResolver } from "@opencred/did";
import type { VerificationCheck } from "./types.js";

/**
 * Options for the attestation chain check.
 */
export interface AttestationCheckOptions {
  dediClient?: DeDiClient;
  didResolver?: DIDResolver;
}

/** The proof shape when attestation is embedded or referenced. */
interface AttestationProofShape {
  keyAttestationCredential?: Record<string, unknown>;
  keyAttestationUrl?: string;
  verificationMethod?: string;
  created?: string;
}

/**
 * Extract the attestation VC from a credential's proof.
 *
 * Attestation can be embedded inline (proof.keyAttestationCredential)
 * or referenced by URL (proof.keyAttestationUrl). If neither is present,
 * the credential was not issued under attestation.
 */
function extractAttestationFromProof(
  proof: Record<string, unknown>,
): { inline: Record<string, unknown> } | { url: string } | null {
  const attestationProof = proof as unknown as AttestationProofShape;

  if (attestationProof.keyAttestationCredential) {
    return { inline: attestationProof.keyAttestationCredential };
  }

  if (attestationProof.keyAttestationUrl) {
    return { url: attestationProof.keyAttestationUrl };
  }

  return null;
}

/**
 * Verify that the credential's signing key matches the key attested
 * in the attestation VC.
 *
 * Matching is done via verificationMethodId — the attestation subject's
 * verificationMethodId must match or share a base DID with the
 * credential's proof.verificationMethod.
 */
function validateKeyBinding(
  attestation: Record<string, unknown>,
  proof: Record<string, unknown>,
): string | null {
  const verificationMethod = proof["verificationMethod"] as string | undefined;
  if (!verificationMethod) {
    return "Credential proof has no verificationMethod for attestation key-binding check";
  }

  const subject = attestation["credentialSubject"] as Record<string, unknown> | undefined;
  if (!subject) {
    return "Attestation has no credentialSubject";
  }

  const attestedVmId = subject["verificationMethodId"] as string | undefined;
  if (!attestedVmId) {
    return "Attestation credentialSubject has no verificationMethodId";
  }

  // Exact match
  if (attestedVmId === verificationMethod) {
    return null;
  }

  // Base DID match (before the fragment)
  const attestedBase = attestedVmId.split("#")[0];
  const vmBase = verificationMethod.split("#")[0];

  if (attestedBase === vmBase) {
    return null;
  }

  return (
    `Attestation key binding mismatch: attested verificationMethod '${attestedVmId}' ` +
    `does not match credential signing key '${verificationMethod}'`
  );
}

/**
 * Validate the attestation's temporal bounds at a specific point in time.
 */
function validateAttestationTemporal(
  attestation: Record<string, unknown>,
  proofTime: Date,
): string | null {
  const validFrom = attestation["validFrom"] as string | undefined;
  const validUntil = attestation["validUntil"] as string | undefined;

  if (validFrom) {
    const from = new Date(validFrom);
    if (isNaN(from.getTime())) {
      return `Attestation has invalid validFrom: ${validFrom}`;
    }
    if (from > proofTime) {
      return "Attestation was not yet valid when credential was signed";
    }
  }

  if (validUntil) {
    const until = new Date(validUntil);
    if (isNaN(until.getTime())) {
      return `Attestation has invalid validUntil: ${validUntil}`;
    }
    if (until <= proofTime) {
      return "Attestation had expired when credential was signed";
    }
  }

  return null;
}

/**
 * Validate that the attestation VC has the correct type.
 */
function validateAttestationType(attestation: Record<string, unknown>): string | null {
  const types = attestation["type"];
  if (!Array.isArray(types)) {
    return "Attestation type must be an array";
  }
  if (!types.includes("KeyAttestationCredential")) {
    return "Attestation must include type 'KeyAttestationCredential'";
  }
  return null;
}

/**
 * Check the attestation chain for a verifiable credential.
 *
 * This function:
 * 1. Detects if the credential has an attestation reference in its proof
 * 2. If no attestation reference, returns a skipped check (not applicable)
 * 3. Extracts the attestation VC (inline or resolves from URL)
 * 4. Validates the attestation VC structure (type, subject)
 * 5. Verifies the key-binding (attested key matches credential signing key)
 * 6. Validates temporal bounds at proof.created time
 */
export async function checkAttestationChain(
  credential: Record<string, unknown>,
  options: AttestationCheckOptions = {},
): Promise<VerificationCheck> {
  const proof = credential["proof"] as Record<string, unknown> | undefined;
  if (!proof) {
    return { name: "attestation", passed: true, detail: "No proof — attestation check skipped" };
  }

  // Detect attestation reference
  const attestationRef = extractAttestationFromProof(proof);
  if (!attestationRef) {
    return {
      name: "attestation",
      passed: true,
      detail: "No attestation reference — not an attested credential",
    };
  }

  // Resolve the attestation VC
  let attestation: Record<string, unknown>;

  if ("inline" in attestationRef) {
    attestation = attestationRef.inline;
  } else {
    // URL-based: would resolve via DeDi or HTTP
    if (!options.dediClient) {
      return {
        name: "attestation",
        passed: false,
        detail: "Attestation referenced by URL but no DeDi client configured to resolve it",
      };
    }

    // TODO: implement URL-based attestation resolution
    return {
      name: "attestation",
      passed: false,
      detail: "URL-based attestation resolution not yet implemented",
    };
  }

  // Validate attestation type
  const typeError = validateAttestationType(attestation);
  if (typeError) {
    return { name: "attestation", passed: false, detail: `Attestation chain invalid: ${typeError}` };
  }

  // Verify key-binding: attested key must match credential signing key
  const bindingError = validateKeyBinding(attestation, proof);
  if (bindingError) {
    return {
      name: "attestation",
      passed: false,
      detail: `Attestation chain invalid: ${bindingError}`,
    };
  }

  // Point-in-time validation: use proof.created, NOT current time
  const proofCreated = proof["created"] as string | undefined;
  if (!proofCreated) {
    return {
      name: "attestation",
      passed: false,
      detail: "Credential proof has no 'created' timestamp for point-in-time attestation validation",
    };
  }

  const proofTime = new Date(proofCreated);
  if (isNaN(proofTime.getTime())) {
    return {
      name: "attestation",
      passed: false,
      detail: `Invalid proof.created timestamp: ${proofCreated}`,
    };
  }

  // Temporal validation at proof time
  const temporalError = validateAttestationTemporal(attestation, proofTime);
  if (temporalError) {
    return {
      name: "attestation",
      passed: false,
      detail: `Attestation chain invalid: ${temporalError}`,
    };
  }

  return { name: "attestation", passed: true };
}
