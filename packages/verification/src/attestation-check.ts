/**
 * Attestation chain verification.
 *
 * Replaces delegation-check.ts. Validates the Key Attestation VC
 * embedded in (or referenced from) a credential's proof.
 *
 * The attestation chain check verifies:
 * 1. The credential has an attestation reference in its proof
 * 2. The attested key matches the credential's signing key
 * 3. The attestation VC signature is cryptographically valid (OpenCred's DSC)
 * 4. The OpenCred DSC chains to a trusted CSCA (X.509 chain validation)
 * 5. The attestation was valid at credential sign time (proof.created)
 */

import { type KeyObject, X509Certificate } from "node:crypto";
import type { DeDiClient } from "@opencred/dedi-client";
import type { DIDResolver } from "@opencred/did";
import type { VerifiableCredential } from "@opencred/vc-core";
import { verifyDataIntegrity } from "./data-integrity.js";
import { checkX509Chain } from "./x509-chain-check.js";
import type { VerificationCheck } from "./types.js";

/**
 * Options for the attestation chain check.
 */
export interface AttestationCheckOptions {
  dediClient?: DeDiClient;
  didResolver?: DIDResolver;
  /**
   * OpenCred's public key for verifying attestation VC signatures.
   * When provided, the attestation VC's proof.verificationMethod is validated
   * against this key directly (bypassing DID resolution for OpenCred's key).
   */
  opencredPublicKey?: KeyObject;
  /**
   * OpenCred's DSC certificate in PEM format for X.509 chain validation.
   * When provided, the attestation VC's DSC -> CSCA chain is validated.
   */
  opencredDscCertificate?: string;
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
 * Matching is done via verificationMethodId -- the attestation subject's
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
 * Validate the URL for fetching an attestation VC.
 * Only HTTPS URLs are allowed to prevent SSRF and man-in-the-middle attacks.
 */
function validateAttestationUrl(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return "Invalid attestation URL";
  }

  if (parsed.protocol !== "https:") {
    return "Attestation URL must use HTTPS";
  }

  return null;
}

/**
 * Fetch an attestation VC from a URL.
 * Only HTTPS URLs are accepted for security.
 */
async function fetchAttestationFromUrl(url: string): Promise<Record<string, unknown>> {
  const response = await globalThis.fetch(url, {
    redirect: "error",
    headers: {
      Accept: "application/vc+ld+json, application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch attestation: HTTP ${response.status}`);
  }

  return (await response.json()) as Record<string, unknown>;
}

/**
 * Verify the attestation VC's Data Integrity proof (cryptographic signature).
 *
 * If an opencredPublicKey is provided, it is used directly.
 * Otherwise, the key is resolved via the attestation's proof.verificationMethod
 * using the DID resolver.
 */
async function verifyAttestationSignature(
  attestation: Record<string, unknown>,
  options: AttestationCheckOptions,
): Promise<string | null> {
  const attestationProof = attestation["proof"] as Record<string, unknown> | undefined;
  if (!attestationProof) {
    return "Attestation VC has no proof";
  }

  // Build a VerifiableCredential-shaped object for verifyDataIntegrity
  const attestationAsVC = attestation as unknown as VerifiableCredential;

  // If we have an explicit OpenCred public key, create a mock DID resolver
  // that returns it for the attestation's verificationMethod DID
  if (options.opencredPublicKey) {
    const attestationVm = attestationProof["verificationMethod"] as string | undefined;
    if (!attestationVm) {
      return "Attestation proof has no verificationMethod";
    }

    const jwk = options.opencredPublicKey.export({ format: "jwk" }) as import("@opencred/did").JWK;
    const did = attestationVm.split("#")[0];

    const mockResolver: DIDResolver = {
      resolve: async (inputDid: string) => {
        if (inputDid !== did) {
          return {
            didDocument: null,
            didResolutionMetadata: { error: "notFound" },
            didDocumentMetadata: {},
          };
        }
        return {
          didDocument: {
            "@context": "https://www.w3.org/ns/did/v1",
            id: did,
            verificationMethod: [
              {
                id: attestationVm,
                type: "JsonWebKey",
                controller: did,
                publicKeyJwk: jwk,
              },
            ],
            assertionMethod: [attestationVm],
          } as import("@opencred/did").DIDDocument,
          didResolutionMetadata: {},
          didDocumentMetadata: {},
        };
      },
    };

    const check = await verifyDataIntegrity(attestationAsVC, mockResolver);
    if (!check.passed) {
      return `Attestation VC signature invalid: ${check.detail ?? "verification failed"}`;
    }
    return null;
  }

  // Fall back to DID resolution
  if (!options.didResolver) {
    return "No OpenCred public key or DID resolver configured to verify attestation signature";
  }

  const check = await verifyDataIntegrity(attestationAsVC, options.didResolver);
  if (!check.passed) {
    return `Attestation VC signature invalid: ${check.detail ?? "verification failed"}`;
  }
  return null;
}

/**
 * Validate the OpenCred DSC certificate itself (expiry, format).
 * This is checked independently of the x5c chain — even when no x5c is
 * present in the attestation proof, we still validate the configured DSC.
 */
function validateDscCertificate(
  dscPem: string,
  proofTime: Date,
): string | null {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(dscPem);
  } catch {
    return "OpenCred DSC certificate is not a valid X.509 certificate";
  }

  const notBefore = new Date(cert.validFrom);
  const notAfter = new Date(cert.validTo);

  if (proofTime < notBefore) {
    return "OpenCred DSC certificate was not yet valid at credential signing time";
  }

  if (proofTime > notAfter) {
    return "OpenCred DSC certificate had expired at credential signing time";
  }

  return null;
}

/**
 * Verify the OpenCred DSC -> CSCA chain on the attestation VC.
 * This validates that OpenCred's signing certificate chains to a trusted root.
 */
async function verifyAttestationX509Chain(
  attestation: Record<string, unknown>,
  options: AttestationCheckOptions,
  proofTime: Date,
): Promise<string | null> {
  // Validate the configured DSC certificate itself (expiry)
  if (options.opencredDscCertificate) {
    const dscError = validateDscCertificate(options.opencredDscCertificate, proofTime);
    if (dscError) {
      return dscError;
    }
  }

  const attestationProof = attestation["proof"] as Record<string, unknown> | undefined;
  if (!attestationProof) {
    return null; // No proof means no x5c to check -- signature check will catch this
  }

  const x5c = attestationProof["x5c"] as string[] | undefined;
  if (!x5c || !Array.isArray(x5c) || x5c.length === 0) {
    return null; // No x5c chain -- not all attestations embed certs
  }

  // If an explicit DSC certificate is provided, validate the chain includes it
  if (options.opencredDscCertificate) {
    // Extract the base64-encoded DER from the PEM
    const pemBody = options.opencredDscCertificate
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s/g, "");

    if (x5c[0] !== pemBody) {
      return "Attestation x5c leaf certificate does not match configured OpenCred DSC";
    }
  }

  const x509Check = await checkX509Chain(attestation, {
    didResolver: options.didResolver,
  });

  if (!x509Check.passed) {
    return `Attestation DSC chain invalid: ${x509Check.detail ?? "chain verification failed"}`;
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
 * 7. Cryptographically verifies the attestation VC's Data Integrity proof
 * 8. Validates the OpenCred DSC -> CSCA certificate chain (if x5c present)
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
    // URL-based attestation resolution
    const urlError = validateAttestationUrl(attestationRef.url);
    if (urlError) {
      return {
        name: "attestation",
        passed: false,
        detail: `Attestation chain invalid: ${urlError}`,
      };
    }

    try {
      attestation = await fetchAttestationFromUrl(attestationRef.url);
    } catch (err) {
      const message = err instanceof Error ? err.message : "unknown error";
      return {
        name: "attestation",
        passed: false,
        detail: `Attestation chain invalid: failed to fetch attestation from URL: ${message}`,
      };
    }
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

  // Cryptographic signature verification of the attestation VC
  const signatureError = await verifyAttestationSignature(attestation, options);
  if (signatureError) {
    return {
      name: "attestation",
      passed: false,
      detail: `Attestation chain invalid: ${signatureError}`,
    };
  }

  // X.509 DSC -> CSCA chain validation on the attestation VC
  const chainError = await verifyAttestationX509Chain(attestation, options, proofTime);
  if (chainError) {
    return {
      name: "attestation",
      passed: false,
      detail: `Attestation chain invalid: ${chainError}`,
    };
  }

  return { name: "attestation", passed: true };
}

// Export internal helpers for testing
export {
  extractAttestationFromProof as _extractAttestationFromProof,
  validateKeyBinding as _validateKeyBinding,
  validateAttestationTemporal as _validateAttestationTemporal,
  validateAttestationType as _validateAttestationType,
  validateAttestationUrl as _validateAttestationUrl,
  fetchAttestationFromUrl as _fetchAttestationFromUrl,
  verifyAttestationSignature as _verifyAttestationSignature,
  verifyAttestationX509Chain as _verifyAttestationX509Chain,
  validateDscCertificate as _validateDscCertificate,
};
