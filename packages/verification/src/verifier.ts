import { VerificationError, assertJwtSize } from "@opencred/shared";
import type { VerifiableCredential } from "@opencred/vc-core";
import { verifyDataIntegrity } from "./data-integrity.js";
import { verifyJwsProof } from "./jws-proof.js";
import {
  verifyVcJwt,
  extractVcJwtCredentialFields,
  crossValidateVcJwtClaims,
} from "./vc-jwt.js";
import { verifySdJwtVc, extractSdJwtVcCredentialFields } from "./sd-jwt-vc.js";
import { checkDates, checkRevocation, checkBitstringStatusList } from "./checks.js";
import { checkX509Chain } from "./x509-chain-check.js";
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
    assertJwtSize(input);
    if (input.includes("~")) {
      return "sd-jwt-vc";
    }
    const dotParts = input.split(".");
    if (dotParts.length === 3) {
      // Distinguish JWS (full VC in payload) from VC-JWT (vc claim in payload)
      // by examining the decoded payload structure.
      try {
        const payload = JSON.parse(Buffer.from(dotParts[1], "base64url").toString());
        if (payload.vc && typeof payload.vc === "object") {
          return "vc-jwt";
        }
        if (payload["@context"] || payload.credentialSubject) {
          return "jws";
        }
      } catch {
        // If payload can't be decoded, fall back to header-based heuristic
      }
      // Fallback: check header for JWT typ
      try {
        const header = JSON.parse(Buffer.from(dotParts[0], "base64url").toString());
        if (header.typ === "JWT") {
          return "vc-jwt";
        }
      } catch {
        // Fall through
      }
      return "jws";
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
  } else if (format === "jws") {
    const signatureCheck = await verifyJwsProof(input as string, config.didResolver);
    checks.push(signatureCheck);

    if (!signatureCheck.passed) {
      return buildResult(checks, signatureCheck);
    }

    // Extract VC fields from the JWS payload
    try {
      const payloadB64 = (input as string).split(".")[1];
      const vcPayload = JSON.parse(Buffer.from(payloadB64, "base64url").toString()) as Record<
        string,
        unknown
      >;
      validFrom = vcPayload.validFrom as string | undefined;
      validUntil = vcPayload.validUntil as string | undefined;
      credentialStatus = vcPayload.credentialStatus as Record<string, unknown> | undefined;
      credentialForRevocationHash = vcPayload;
    } catch {
      // Payload extraction is best-effort for date/revocation checks
    }
  } else if (format === "vc-jwt") {
    const { check, payload } = await verifyVcJwt(input as string, config.didResolver);
    checks.push(check);

    if (!check.passed || !payload) {
      return buildResult(checks, check);
    }

    // VC-JOSE-COSE §3.3.1 / §3.3.2 — `jti` MUST equal `vc.id` and `sub`
    // MUST equal `vc.credentialSubject.id` when the envelope uses the
    // DM 1.1 nested layout. Signature verification alone does not enforce
    // this, so a malicious issuer could reuse a valid envelope signature
    // around a swapped inner `vc` object unless we cross-validate.
    const crossErrors = crossValidateVcJwtClaims(payload);
    if (crossErrors.length > 0) {
      const crossCheck: VerificationCheck = {
        name: "vc-jwt-claims",
        passed: false,
        detail: crossErrors.join("; "),
      };
      checks.push(crossCheck);
      return buildResult(checks, crossCheck);
    }
    checks.push({ name: "vc-jwt-claims", passed: true });

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
    const bslCheck = await checkBitstringStatusList(credentialStatus, {
      didResolver: config.didResolver,
    });
    checks.push(bslCheck);
    if (!bslCheck.passed) {
      if (bslCheck.detail?.includes("revoked")) {
        return { code: "REVOKED", verified: false, checks };
      }
      return { code: "UNRESOLVABLE", verified: false, checks };
    }
  }

  // X.509 certificate chain check (validates DSC → CSCA trust chain).
  //
  // The check is fail-closed when an `x5c` chain is present: it requires a
  // configured trust anchor list and a resolvable DID for the issuer. See
  // nfh-trust-labs/opencred#316. Credentials without `x5c` (e.g. did:web with
  // self-published keys) are unaffected — the check returns passed without
  // requiring trust anchors.
  if (format === "data-integrity") {
    const x509Check = await checkX509Chain(input as Record<string, unknown>, {
      didResolver: config.didResolver,
      trustAnchors: config.trustAnchors,
    });
    checks.push(x509Check);
    if (!x509Check.passed) {
      return { code: "INVALID", verified: false, checks };
    }
  }

  return { code: "VALID", verified: true, checks };
}

function buildResult(
  checks: VerificationCheck[],
  failedCheck: VerificationCheck,
): CredentialVerificationResult {
  const isUnresolvable = failedCheck.detail?.includes("Unable to resolve");
  const isContextMissing = failedCheck.detail?.includes("Missing JSON-LD context");
  return {
    code: isContextMissing ? "CONTEXT_MISSING" : isUnresolvable ? "UNRESOLVABLE" : "INVALID",
    verified: false,
    checks,
  };
}
