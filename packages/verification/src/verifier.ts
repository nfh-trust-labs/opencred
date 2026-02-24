import { VerificationError } from "@opencred/shared";
import type { VerifiableCredential } from "@opencred/vc-core";
import { verifyDataIntegrity } from "./data-integrity.js";
import { verifyVcJwt, extractVcJwtCredentialFields } from "./vc-jwt.js";
import { verifySdJwtVc, extractSdJwtVcCredentialFields } from "./sd-jwt-vc.js";
import { checkDates, checkRevocation, checkBitstringStatusList } from "./checks.js";
import { checkDelegationChain } from "./delegation-check.js";
import type {
  CredentialFormat,
  CredentialVerificationResult,
  VerificationCheck,
  VerificationInput,
  VerifierConfig,
} from "./types.js";

/**
 * Detect the format of a credential input.
 *
 * - Object with `proof` → Data Integrity
 * - String containing `~` → SD-JWT VC
 * - String with 3 dot-separated parts → VC-JWT
 */
export function detectFormat(input: VerificationInput): CredentialFormat {
  if (typeof input === "object" && input !== null) {
    if ("proof" in input) {
      return "data-integrity";
    }
    throw new VerificationError(
      "Object input must have a 'proof' property for Data Integrity verification",
    );
  }

  if (typeof input === "string") {
    if (input.includes("~")) {
      return "sd-jwt-vc";
    }
    const dotParts = input.split(".");
    if (dotParts.length === 3) {
      return "vc-jwt";
    }
    throw new VerificationError("String input is not a valid VC-JWT or SD-JWT VC");
  }

  throw new VerificationError(
    "Input must be an object (Data Integrity) or string (VC-JWT / SD-JWT VC)",
  );
}

/**
 * Verify a credential in any supported format.
 *
 * Dispatches to the appropriate format-specific verifier, then runs common checks
 * (date validation, revocation, BitstringStatusList).
 */
export async function verifyCredential(
  input: VerificationInput,
  config: VerifierConfig = {},
): Promise<CredentialVerificationResult> {
  const format = detectFormat(input);
  const checks: VerificationCheck[] = [];

  let validFrom: string | undefined;
  let validUntil: string | undefined;
  let credentialStatus: Record<string, unknown> | undefined;
  let credentialForRevocationHash: unknown;

  if (format === "data-integrity") {
    const credential = input as unknown as VerifiableCredential;
    const signatureCheck = await verifyDataIntegrity(credential, config.didResolver);
    checks.push(signatureCheck);

    if (!signatureCheck.passed) {
      return buildResult(checks, signatureCheck);
    }

    validFrom = credential.validFrom;
    validUntil = credential.validUntil;
    credentialStatus = credential.credentialStatus as Record<string, unknown> | undefined;
    credentialForRevocationHash = credential;
  } else if (format === "vc-jwt") {
    const { check, payload } = await verifyVcJwt(input as string, config.didResolver);
    checks.push(check);

    if (!check.passed || !payload) {
      return buildResult(checks, check);
    }

    const fields = extractVcJwtCredentialFields(payload);
    validFrom = fields.validFrom;
    validUntil = fields.validUntil;
    credentialStatus = fields.credentialStatus;
    credentialForRevocationHash = payload.vc ?? payload;
  } else {
    const { check, payload, resolvedClaims } = await verifySdJwtVc(
      input as string,
      config.didResolver,
    );
    checks.push(check);

    if (!check.passed || !payload || !resolvedClaims) {
      return buildResult(checks, check);
    }

    const fields = extractSdJwtVcCredentialFields(payload, resolvedClaims);
    validFrom = fields.validFrom;
    validUntil = fields.validUntil;
    credentialStatus = fields.credentialStatus;
    credentialForRevocationHash = resolvedClaims;
  }

  // Date checks
  const dateCheck = checkDates(validFrom, validUntil);
  checks.push(dateCheck);
  if (!dateCheck.passed) {
    const isExpired =
      dateCheck.detail?.includes("expired") || dateCheck.detail?.includes("validUntil");
    return {
      code: isExpired ? "EXPIRED" : "INVALID",
      verified: false,
      checks,
    };
  }

  // Revocation checks
  if (config.dediClient && credentialForRevocationHash) {
    const revocationCheck = await checkRevocation(credentialForRevocationHash, config.dediClient);
    checks.push(revocationCheck);
    if (!revocationCheck.passed) {
      if (revocationCheck.detail?.includes("revoked")) {
        return { code: "REVOKED", verified: false, checks };
      }
      return { code: "UNRESOLVABLE", verified: false, checks };
    }
  }

  // BitstringStatusList check
  if (credentialStatus && credentialStatus["type"] === "BitstringStatusListEntry") {
    const bslCheck = await checkBitstringStatusList(credentialStatus);
    checks.push(bslCheck);
    if (!bslCheck.passed) {
      if (bslCheck.detail?.includes("revoked")) {
        return { code: "REVOKED", verified: false, checks };
      }
      return { code: "UNRESOLVABLE", verified: false, checks };
    }
  }

  // Delegation chain check (only runs if credential has a delegation reference)
  if (format === "data-integrity") {
    const delegationCheck = await checkDelegationChain(
      input as Record<string, unknown>,
      { dediClient: config.dediClient, didResolver: config.didResolver },
    );
    checks.push(delegationCheck);
    if (!delegationCheck.passed) {
      return { code: "DELEGATION_INVALID", verified: false, checks };
    }
  }

  return { code: "VALID", verified: true, checks };
}

function buildResult(
  checks: VerificationCheck[],
  failedCheck: VerificationCheck,
): CredentialVerificationResult {
  const isUnresolvable = failedCheck.detail?.includes("Unable to resolve");
  return {
    code: isUnresolvable ? "UNRESOLVABLE" : "INVALID",
    verified: false,
    checks,
  };
}
