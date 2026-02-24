import { createPublicKey, type KeyObject } from "node:crypto";
import { validateDelegationCertificate, resolveDelegation } from "@opencred/delegation";
import type {
  DelegationCertificate,
  DelegatedCredentialProof,
  ValidateDelegationResult,
} from "@opencred/delegation";
import type { DeDiClient } from "@opencred/dedi-client";
import type { DIDResolver } from "@opencred/did";
import { publicKeyFromMultibase } from "./key-utils.js";
import type { VerificationCheck } from "./types.js";

/**
 * Options for the delegation chain check.
 */
export interface DelegationCheckOptions {
  dediClient?: DeDiClient;
  didResolver?: DIDResolver;
}

/**
 * Extract the delegation certificate from a credential's proof.
 *
 * Delegation can be embedded inline (proof.delegationCertificate) or
 * referenced by URL (proof.delegationCertificateUrl). If neither is
 * present, the credential was not issued under delegation.
 */
function extractDelegationFromProof(
  proof: Record<string, unknown>,
): { inline: DelegationCertificate } | { url: string } | null {
  const delegatedProof = proof as unknown as DelegatedCredentialProof;

  if (delegatedProof.delegationCertificate) {
    return { inline: delegatedProof.delegationCertificate };
  }

  if (delegatedProof.delegationCertificateUrl) {
    return { url: delegatedProof.delegationCertificateUrl };
  }

  return null;
}

/**
 * Extract the credential type for scope checking.
 * Returns the most specific type (not "VerifiableCredential").
 */
function extractCredentialType(credential: Record<string, unknown>): string | undefined {
  const types = credential["type"];
  if (!Array.isArray(types)) return undefined;

  const specific = types.find(
    (t: unknown) => typeof t === "string" && t !== "VerifiableCredential",
  );
  return typeof specific === "string" ? specific : undefined;
}

/**
 * Verify that the credential's signing key (proof.verificationMethod) matches
 * the delegatee key authorised in the delegation certificate.
 *
 * Matching rules:
 * - Exact match (delegatee.id === proof.verificationMethod)
 * - Base DID match (the DID part before the fragment matches)
 */
function validateDelegateeMatchesSigningKey(
  certificate: DelegationCertificate,
  proof: Record<string, unknown>,
): string | null {
  const verificationMethod = proof["verificationMethod"] as string | undefined;
  if (!verificationMethod) {
    return "Credential proof has no verificationMethod for delegatee binding check";
  }

  const delegateeId = certificate.delegatee.id;

  // Exact match
  if (delegateeId === verificationMethod) {
    return null;
  }

  // Base DID match (before the fragment)
  const delegateeBase = delegateeId.split("#")[0];
  const vmBase = verificationMethod.split("#")[0];

  if (delegateeBase === vmBase) {
    return null;
  }

  return (
    `Delegation delegatee '${delegateeId}' does not match ` +
    `credential signing key '${verificationMethod}'`
  );
}

/**
 * Resolve the delegator's public key from their DID document.
 *
 * Returns undefined if the key cannot be resolved. This is non-fatal;
 * proof verification is best-effort when a DID resolver is available.
 */
async function resolveDelegatorPublicKey(
  certificate: DelegationCertificate,
  didResolver?: DIDResolver,
): Promise<KeyObject | undefined> {
  if (!didResolver) {
    return undefined;
  }

  const certProof = certificate.proof;
  if (!certProof?.verificationMethod) {
    return undefined;
  }

  const delegatorDid = certProof.verificationMethod.split("#")[0];

  try {
    const resolution = await didResolver.resolve(delegatorDid);
    if (!resolution.didDocument?.verificationMethod?.length) {
      return undefined;
    }

    const vmId = certProof.verificationMethod;
    const fragmentId = vmId.includes("#") ? `#${vmId.split("#")[1]}` : undefined;

    const vm = resolution.didDocument.verificationMethod.find(
      (m) => m.id === vmId || (fragmentId && m.id === fragmentId),
    );

    if (!vm) {
      return undefined;
    }

    if (vm.publicKeyMultibase) {
      return publicKeyFromMultibase(vm.publicKeyMultibase) ?? undefined;
    }

    if (vm.publicKeyJwk) {
      return createPublicKey({ key: vm.publicKeyJwk, format: "jwk" });
    }

    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Check the delegation chain for a verifiable credential.
 *
 * This function:
 * 1. Detects if the credential has a delegation reference in its proof
 * 2. If no delegation reference, returns a skipped check (not applicable)
 * 3. Extracts or resolves the delegation certificate
 * 4. Verifies the delegatee-key binding (proof.verificationMethod matches
 *    delegation.delegatee.id)
 * 5. Resolves the delegator public key and verifies the delegation cert proof
 * 6. Validates the delegation certificate at the point in time when the
 *    credential was signed (proof.created), NOT the current time
 * 7. Checks that the delegation scope covers the credential type
 *
 * Security invariant: delegation certificates are trust boundaries.
 * Always validate scope, validFrom, validUntil before accepting.
 */
export async function checkDelegationChain(
  credential: Record<string, unknown>,
  options: DelegationCheckOptions = {},
): Promise<VerificationCheck> {
  const proof = credential["proof"] as Record<string, unknown> | undefined;
  if (!proof) {
    return { name: "delegation", passed: true, detail: "No proof — delegation check skipped" };
  }

  // Detect delegation reference
  const delegationRef = extractDelegationFromProof(proof);
  if (!delegationRef) {
    return {
      name: "delegation",
      passed: true,
      detail: "No delegation reference — not a delegated credential",
    };
  }

  // Resolve the delegation certificate
  let certificate: DelegationCertificate;

  if ("inline" in delegationRef) {
    certificate = delegationRef.inline;
  } else {
    // Reference-based: resolve via DeDi
    if (!options.dediClient) {
      return {
        name: "delegation",
        passed: false,
        detail: "Delegation referenced by URL but no DeDi client configured to resolve it",
      };
    }

    try {
      certificate = await resolveDelegation(options.dediClient, {
        delegationId: delegationRef.url,
      });
    } catch {
      return {
        name: "delegation",
        passed: false,
        detail: "Failed to resolve delegation certificate from DeDi",
      };
    }
  }

  // Verify delegatee-key binding: proof.verificationMethod must match delegation.delegatee.id
  const bindingError = validateDelegateeMatchesSigningKey(certificate, proof);
  if (bindingError) {
    return {
      name: "delegation",
      passed: false,
      detail: `Delegation chain invalid: ${bindingError}`,
    };
  }

  // Point-in-time validation: use proof.created, NOT current time
  const proofCreated = proof["created"] as string | undefined;
  if (!proofCreated) {
    return {
      name: "delegation",
      passed: false,
      detail: "Credential proof has no 'created' timestamp for point-in-time delegation validation",
    };
  }

  const proofTime = new Date(proofCreated);
  if (isNaN(proofTime.getTime())) {
    return {
      name: "delegation",
      passed: false,
      detail: `Invalid proof.created timestamp: ${proofCreated}`,
    };
  }

  // Check credential type scope
  const credentialType = extractCredentialType(credential);

  // Resolve the delegator's public key for proof verification (best-effort)
  const delegatorPublicKey = await resolveDelegatorPublicKey(certificate, options.didResolver);

  // Validate the delegation certificate (temporal, structural, scope, and proof if key available)
  let validationResult: ValidateDelegationResult;
  try {
    validationResult = await validateDelegationCertificate(certificate, {
      now: proofTime,
      credentialType,
      delegatorPublicKey,
    });
  } catch {
    return {
      name: "delegation",
      passed: false,
      detail: "Delegation certificate validation threw an error",
    };
  }

  if (!validationResult.valid) {
    const reason = validationResult.errors.join("; ");
    return {
      name: "delegation",
      passed: false,
      detail: `Delegation chain invalid: ${reason}`,
    };
  }

  return { name: "delegation", passed: true };
}
