import { DelegationError } from "@opencred/shared";
import type { VerifiableCredential, Proof } from "@opencred/vc-core";
import type { DeDiClient } from "@opencred/dedi-client";
import { validateDelegationCertificate } from "./certificate.js";
import { isDelegationRevoked } from "./registry.js";
import type {
  DelegationCertificate,
  DelegatedCredentialProof,
  ValidateDelegationOptions,
} from "./types.js";

/**
 * Result of a delegation chain validation.
 */
export interface ChainValidationResult {
  valid: boolean;
  errors: string[];
  /** The resolved delegation certificate, if found. */
  delegation?: DelegationCertificate;
}

/**
 * Function signature for resolving a delegation certificate by ID.
 */
export type DelegationResolver = (delegationId: string) => Promise<DelegationCertificate>;

/**
 * Options for delegation chain validation.
 */
export interface ChainValidationOptions extends ValidateDelegationOptions {
  /** When provided, check whether the delegation has been revoked in DeDi. */
  dediClient?: DeDiClient;
}

export async function validateDelegationChain(
  credential: VerifiableCredential,
  resolver: DelegationResolver,
  options?: ChainValidationOptions,
): Promise<ChainValidationResult> {
  const errors: string[] = [];

  if (!credential.proof) {
    return { valid: false, errors: ["Credential has no proof"] };
  }

  // 1. Locate the delegation certificate
  const delegation = await locateDelegation(credential.proof, resolver, errors);
  if (!delegation) {
    return { valid: false, errors };
  }

  // 2. Verify the delegation names the correct signing key
  validateDelegateeMatchesSigningKey(delegation, credential.proof, errors);

  // 3. Validate the delegation certificate (temporal, structural, scope)
  const proofCreated = credential.proof.created;
  const validationTime = options?.now ?? (proofCreated ? new Date(proofCreated) : new Date());

  const validationResult = await validateDelegationCertificate(delegation, {
    ...options,
    now: validationTime,
  });

  if (!validationResult.valid) {
    errors.push(...validationResult.errors);
  }

  // 4. Revocation check (when DeDi client is available)
  if (options?.dediClient && delegation.id) {
    try {
      const revoked = await isDelegationRevoked(options.dediClient, delegation.id);
      if (revoked) {
        errors.push(`Delegation '${delegation.id}' has been revoked`);
      }
    } catch (error) {
      errors.push(
        `Failed to check delegation revocation status: ${error instanceof Error ? error.message : "unknown error"}`,
      );
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    delegation,
  };
}

async function locateDelegation(
  proof: Proof,
  resolver: DelegationResolver,
  errors: string[],
): Promise<DelegationCertificate | undefined> {
  const delegatedProof = proof as DelegatedCredentialProof;

  if (delegatedProof.delegationCertificate) {
    return delegatedProof.delegationCertificate;
  }

  if (delegatedProof.delegationCertificateUrl) {
    try {
      const url = delegatedProof.delegationCertificateUrl;
      const delegationId = extractDelegationId(url);
      return await resolver(delegationId);
    } catch (error) {
      if (error instanceof DelegationError) {
        errors.push(`Failed to resolve delegation: ${error.message}`);
      } else {
        errors.push(
          `Failed to resolve delegation: ${error instanceof Error ? error.message : "unknown error"}`,
        );
      }
      return undefined;
    }
  }

  errors.push("Credential proof contains no delegation certificate (inline or referenced)");
  return undefined;
}

function extractDelegationId(url: string): string {
  if (url.startsWith("urn:")) {
    return url;
  }

  try {
    const parsed = new URL(url);
    const segments = parsed.pathname.split("/").filter(Boolean);
    const lastSegment = segments[segments.length - 1];
    if (!lastSegment) {
      throw new DelegationError(`Cannot extract delegation ID from URL: ${url}`);
    }
    return decodeURIComponent(lastSegment);
  } catch (error) {
    if (error instanceof DelegationError) throw error;
    throw new DelegationError(`Invalid delegation URL: ${url}`);
  }
}

export function validateDelegateeMatchesSigningKey(
  delegation: DelegationCertificate,
  proof: Proof,
  errors: string[],
): void {
  if (!proof.verificationMethod) {
    errors.push("Credential proof has no verificationMethod");
    return;
  }

  const delegateeId = delegation.delegatee.id;
  const verificationMethod = proof.verificationMethod;

  if (delegateeId !== verificationMethod) {
    errors.push(
      `Delegation delegatee '${delegateeId}' does not match ` +
        `credential signing key '${verificationMethod}'`,
    );
  }
}
