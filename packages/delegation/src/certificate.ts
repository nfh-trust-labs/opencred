import { randomUUID } from "node:crypto";
import { DelegationError, ValidationError } from "@opencred/shared";
import { verifyProof } from "@opencred/crypto";
import { W3C_CREDENTIALS_V2_CONTEXT } from "@opencred/vc-core";
import type { VerifiableCredential } from "@opencred/vc-core";
import type {
  CreateDelegationParams,
  DelegationCertificate,
  DelegatedCredentialProof,
  EmbedDelegationOptions,
  UnsignedDelegationCertificate,
  ValidateDelegationOptions,
  ValidateDelegationResult,
} from "./types.js";
import { OPENCRED_DELEGATION_CONTEXT } from "./types.js";

/**
 * Create an unsigned delegation certificate.
 *
 * The returned certificate must be signed by the delegator (issuer) before
 * it can be used. Signing is performed via `@opencred/crypto` — either
 * `signCredential()` for server-side keys or the prepare/complete two-phase
 * flow for browser-based signing.
 *
 * @param params - Delegation certificate parameters.
 * @returns An unsigned delegation certificate ready for signing.
 * @throws {ValidationError} if required parameters are missing or invalid.
 */
export function createDelegationCertificate(
  params: CreateDelegationParams,
): UnsignedDelegationCertificate {
  validateCreateParams(params);

  const certificate: UnsignedDelegationCertificate = {
    "@context": [W3C_CREDENTIALS_V2_CONTEXT, OPENCRED_DELEGATION_CONTEXT],
    id: params.id ?? `urn:uuid:${randomUUID()}`,
    type: ["VerifiableCredential", "DelegationCertificate"],
    delegator: { ...params.delegator },
    delegatee: { ...params.delegatee },
    scope: {
      credentialTypes: [...params.scope.credentialTypes],
      namespaces: [...params.scope.namespaces],
      ...(params.scope.maxIssuanceCount !== undefined
        ? { maxIssuanceCount: params.scope.maxIssuanceCount }
        : {}),
    },
    validFrom: params.validFrom,
    validUntil: params.validUntil,
    authorisationPath: params.authorisationPath,
  };

  if (params.credentialStatus) {
    certificate.credentialStatus = { ...params.credentialStatus };
  }

  return certificate;
}

/**
 * Validate a delegation certificate.
 *
 * Checks structural integrity, temporal validity, scope constraints, and
 * optionally verifies the cryptographic proof.
 *
 * Security invariant: delegation certificates are trust boundaries — always
 * validate scope, validFrom, validUntil, and authorised key ID before
 * accepting a delegation cert. Never skip validation even in dev/test.
 *
 * @param certificate - The delegation certificate to validate.
 * @param options - Validation options (time override, scope checks, proof verification).
 * @returns Validation result with status and any errors.
 */
export async function validateDelegationCertificate(
  certificate: DelegationCertificate,
  options: ValidateDelegationOptions = {},
): Promise<ValidateDelegationResult> {
  const errors: string[] = [];

  // 1. Structural validation
  validateStructure(certificate, errors);

  // 2. Temporal validation (always runs, never skip per CLAUDE.md)
  const now = options.now ?? new Date();
  const temporallyValid = validateTemporalValidity(certificate, now, errors);

  // 3. Scope validation
  if (options.credentialType) {
    validateCredentialTypeScope(certificate, options.credentialType, errors);
  }
  if (options.namespace) {
    validateNamespaceScope(certificate, options.namespace, errors);
  }

  // 4. Proof verification (optional)
  if (options.delegatorPublicKey && certificate.proof) {
    await validateProof(certificate, options, errors);
  } else if (options.delegatorPublicKey && !certificate.proof) {
    errors.push(
      "Delegation certificate has no proof but a delegator public key was provided for verification",
    );
  }

  // Determine status
  let status: "active" | "expired" | "revoked" | "not-yet-valid" = "active";
  if (!temporallyValid) {
    const validFrom = new Date(certificate.validFrom);
    const validUntil = new Date(certificate.validUntil);
    if (now > validUntil) {
      status = "expired";
    } else if (now < validFrom) {
      status = "not-yet-valid";
    }
  }

  return {
    valid: errors.length === 0,
    status,
    errors,
  };
}

/**
 * Embed or reference a delegation certificate in a verifiable credential.
 *
 * The delegation is attached to the credential's proof object so verifiers
 * can locate it during delegation chain validation (PRD Section 8.4).
 *
 * @param credential - The signed verifiable credential.
 * @param delegation - The signed delegation certificate.
 * @param options - Embedding options (inline vs. reference).
 * @returns A new credential object with the delegation attached to the proof.
 * @throws {DelegationError} if the credential has no proof or options are invalid.
 */
export function embedDelegation(
  credential: VerifiableCredential,
  delegation: DelegationCertificate,
  options: EmbedDelegationOptions = {},
): VerifiableCredential {
  if (!credential.proof) {
    throw new DelegationError("Cannot embed delegation: credential has no proof");
  }

  const inline = options.inline !== false; // Default to inline

  if (!inline && !options.delegationUrl) {
    throw new DelegationError(
      "delegationUrl is required when embedding by reference (inline=false)",
    );
  }

  if (!delegation.proof) {
    throw new DelegationError("Cannot embed an unsigned delegation certificate");
  }

  const proof: DelegatedCredentialProof = {
    ...credential.proof,
  };

  if (inline) {
    proof.delegationCertificate = delegation;
  } else {
    proof.delegationCertificateUrl = options.delegationUrl;
  }

  return {
    ...credential,
    proof,
  };
}

/**
 * Check whether a delegation certificate authorises signing a specific
 * credential type within a given namespace at a specific point in time.
 *
 * This is a convenience function combining temporal and scope checks.
 *
 * @param certificate - The delegation certificate to check.
 * @param credentialType - The credential type to check (e.g., "UniversityDegreeCredential").
 * @param namespace - The namespace to check (e.g., "education").
 * @param atTime - The point in time to check validity. Defaults to now.
 * @returns true if the delegation authorises this issuance.
 */
export function isDelegationAuthorised(
  certificate: DelegationCertificate,
  credentialType?: string,
  namespace?: string,
  atTime?: Date,
): boolean {
  const now = atTime ?? new Date();
  const validFrom = new Date(certificate.validFrom);
  const validUntil = new Date(certificate.validUntil);

  if (now < validFrom || now > validUntil) {
    return false;
  }

  if (credentialType && certificate.scope.credentialTypes.length > 0) {
    if (!certificate.scope.credentialTypes.includes(credentialType)) {
      return false;
    }
  }

  if (namespace && certificate.scope.namespaces.length > 0) {
    if (!certificate.scope.namespaces.includes(namespace)) {
      return false;
    }
  }

  return true;
}

/**
 * Compute the status of a delegation certificate at the current time.
 */
export function computeDelegationStatus(
  certificate: DelegationCertificate | UnsignedDelegationCertificate,
  now: Date = new Date(),
): "active" | "expired" | "not-yet-valid" {
  const validFrom = new Date(certificate.validFrom);
  const validUntil = new Date(certificate.validUntil);

  if (now < validFrom) return "not-yet-valid";
  if (now > validUntil) return "expired";
  return "active";
}

// --- Internal validation helpers ---

function validateCreateParams(params: CreateDelegationParams): void {
  if (!params.delegator?.id?.trim()) {
    throw new ValidationError("delegator.id is required");
  }
  if (!params.delegatee?.id?.trim()) {
    throw new ValidationError("delegatee.id is required");
  }
  if (!params.validFrom) {
    throw new ValidationError("validFrom is required");
  }
  if (!params.validUntil) {
    throw new ValidationError("validUntil is required");
  }
  if (isNaN(Date.parse(params.validFrom))) {
    throw new ValidationError(`Invalid validFrom date: ${params.validFrom}`);
  }
  if (isNaN(Date.parse(params.validUntil))) {
    throw new ValidationError(`Invalid validUntil date: ${params.validUntil}`);
  }
  if (Date.parse(params.validUntil) <= Date.parse(params.validFrom)) {
    throw new ValidationError("validUntil must be after validFrom");
  }
  if (!params.scope) {
    throw new ValidationError("scope is required");
  }
  if (!params.authorisationPath) {
    throw new ValidationError("authorisationPath is required");
  }
  if (
    params.scope.maxIssuanceCount !== undefined &&
    (params.scope.maxIssuanceCount <= 0 || !Number.isInteger(params.scope.maxIssuanceCount))
  ) {
    throw new ValidationError("maxIssuanceCount must be a positive integer");
  }
}

function validateStructure(certificate: DelegationCertificate, errors: string[]): void {
  if (!certificate.id) {
    errors.push("Missing certificate id");
  }
  if (
    !certificate.type ||
    !Array.isArray(certificate.type) ||
    !certificate.type.includes("DelegationCertificate")
  ) {
    errors.push("type must include 'DelegationCertificate'");
  }
  if (
    certificate.type &&
    Array.isArray(certificate.type) &&
    !certificate.type.includes("VerifiableCredential")
  ) {
    errors.push("type must include 'VerifiableCredential'");
  }
  if (!certificate.delegator?.id) {
    errors.push("Missing delegator.id");
  }
  if (!certificate.delegatee?.id) {
    errors.push("Missing delegatee.id");
  }
  if (!certificate.scope) {
    errors.push("Missing scope");
  }
  if (!certificate.validFrom) {
    errors.push("Missing validFrom");
  }
  if (!certificate.validUntil) {
    errors.push("Missing validUntil");
  }
  if (!certificate.authorisationPath) {
    errors.push("Missing authorisationPath");
  }
}

function validateTemporalValidity(
  certificate: DelegationCertificate,
  now: Date,
  errors: string[],
): boolean {
  const validFrom = new Date(certificate.validFrom);
  const validUntil = new Date(certificate.validUntil);

  if (isNaN(validFrom.getTime())) {
    errors.push(`Invalid validFrom date: ${certificate.validFrom}`);
    return false;
  }
  if (isNaN(validUntil.getTime())) {
    errors.push(`Invalid validUntil date: ${certificate.validUntil}`);
    return false;
  }
  if (validUntil <= validFrom) {
    errors.push("validUntil must be after validFrom");
    return false;
  }

  if (now < validFrom) {
    errors.push(`Delegation is not yet valid (validFrom: ${certificate.validFrom})`);
    return false;
  }
  if (now > validUntil) {
    errors.push(`Delegation has expired (validUntil: ${certificate.validUntil})`);
    return false;
  }
  return true;
}

function validateCredentialTypeScope(
  certificate: DelegationCertificate,
  credentialType: string,
  errors: string[],
): void {
  if (
    certificate.scope.credentialTypes.length > 0 &&
    !certificate.scope.credentialTypes.includes(credentialType)
  ) {
    errors.push(
      `Credential type '${credentialType}' is not within delegation scope. ` +
        `Allowed types: ${certificate.scope.credentialTypes.join(", ")}`,
    );
  }
}

function validateNamespaceScope(
  certificate: DelegationCertificate,
  namespace: string,
  errors: string[],
): void {
  if (
    certificate.scope.namespaces.length > 0 &&
    !certificate.scope.namespaces.includes(namespace)
  ) {
    errors.push(
      `Namespace '${namespace}' is not within delegation scope. ` +
        `Allowed namespaces: ${certificate.scope.namespaces.join(", ")}`,
    );
  }
}

async function validateProof(
  certificate: DelegationCertificate,
  options: ValidateDelegationOptions,
  errors: string[],
): Promise<void> {
  // The delegation certificate is structurally similar to a VC for proof
  // verification purposes. We cast it to VerifiableCredential to reuse
  // the existing proof verification infrastructure.
  const asVC = certificate as unknown as VerifiableCredential;
  const result = await verifyProof(asVC, {
    publicKey: options.delegatorPublicKey,
  });
  if (!result.verified) {
    errors.push(`Proof verification failed: ${result.error ?? "unknown error"}`);
  }
}
