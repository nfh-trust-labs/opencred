import { VerificationError, assertJwtSize } from "@opencred/shared";
import type { VerifiableCredential } from "@opencred/vc-core";
import { isCanonicalizingProofFormat } from "@opencred/crypto";
import { verifyDataIntegrity } from "./data-integrity.js";
import { verifyJws2020Proof } from "./jws-2020.js";
import { verifyJwsProof } from "./jws-proof.js";
import {
  verifyVcJwt,
  extractVcJwtCredentialFields,
  crossValidateVcJwtClaims,
  isJwsEnvelope,
  checkJwsEnvelopeConsistency,
} from "./vc-jwt.js";
import { verifySdJwtVc, extractSdJwtVcCredentialFields } from "./sd-jwt-vc.js";
import {
  checkDates,
  checkRevocation,
  checkBitstringStatusList,
  checkKeyStatus,
  checkRegistryAnchor,
} from "./checks.js";
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
      const proof = (input as { proof?: unknown }).proof;
      if (
        typeof proof === "object" &&
        proof !== null &&
        (proof as Record<string, unknown>)["type"] === "JsonWebSignature2020" &&
        typeof (proof as Record<string, unknown>)["jws"] === "string" &&
        // The vc-jwt envelope shape (proof.jwt) takes precedence — a stray
        // `jws` member on an envelope must not reroute classification, or
        // detectFormat would diverge from verifyCredential's envelope-first
        // dispatch and label a never-verified proof.jws as the operative
        // signature.
        typeof (proof as Record<string, unknown>)["jwt"] !== "string"
      ) {
        return "jws-2020";
      }
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
  // VC-JWT envelope: the canonical issuance output for `proofFormat:
  // "vc-jwt"` is a JSON-LD credential wrapping its compact token as
  // `proof: { type: "JsonWebSignature2020", jwt }` — this is what PDF
  // info-dicts, PixelPass QRs, and JSON exports carry. Only the inner JWT
  // is signed, so: (1) cross-validate the outer JSON against the signed
  // payload (a tampered display copy must not verify), then (2) run the
  // inner token through the standard VC-JWT pipeline below.
  if (isJwsEnvelope(input)) {
    const envelope = input as Record<string, unknown>;
    const jwt = (envelope["proof"] as { jwt: string }).jwt;
    const envelopeCheck = checkJwsEnvelopeConsistency(envelope, jwt);
    if (!envelopeCheck.passed) {
      return { code: "INVALID", verified: false, checks: [envelopeCheck] };
    }
    const inner = await verifyCredential(jwt, config);
    return { ...inner, checks: [envelopeCheck, ...inner.checks] };
  }

  const format = detectFormat(input);
  const checks: VerificationCheck[] = [];

  let validFrom: string | undefined;
  let validUntil: string | undefined;
  let credentialStatus: Record<string, unknown> | undefined;
  let credentialForRevocationHash: unknown;

  if (isCanonicalizingProofFormat(format)) {
    const credential = input as unknown as VerifiableCredential;
    const signatureCheck =
      format === "jws-2020"
        ? await verifyJws2020Proof(credential, config.didResolver)
        : await verifyDataIntegrity(credential, config.didResolver);
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

    // VC-JOSE-COSE §3.3.1 / §3.3.2 — `jti` MUST equal the credential `id`
    // and `sub` MUST equal `credentialSubject.id`, for both the DM 1.1
    // nested (`vc`) layout and the DM 2.0 flat layout. Signature
    // verification alone does not enforce this, so a malicious issuer
    // could reuse a valid envelope signature around swapped credential
    // fields unless we cross-validate.
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
    // Forward the caller's KB-JWT expectations (audience, nonce, vct) to
    // the SD-JWT VC verifier. For KB-bearing presentations these MUST be
    // supplied by the relying party per SD-JWT VC §4.3.1, or the KB
    // claims cannot be validated and presentation replay is possible.
    const { check, payload, resolvedClaims } = await verifySdJwtVc(
      input as string,
      config.didResolver,
      config.sdJwtVc,
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

  // Revocation checks.
  //
  // We deliberately removed `checkIssuerAttribution` — the bare issuer DID
  // (a string visible elsewhere in the verifier UI) is sufficient as
  // identity; no separate advisory check is needed.
  if (config.dediClient && credentialForRevocationHash) {
    const revocationCheck = await checkRevocation(credentialForRevocationHash, config.dediClient);
    checks.push(revocationCheck);
    if (!revocationCheck.passed) {
      if (revocationCheck.detail?.includes("revoked")) {
        return { code: "REVOKED", verified: false, checks };
      }
      return { code: "UNRESOLVABLE", verified: false, checks };
    }
  } else if (credentialStatus != null) {
    // The issuer explicitly committed to a revocation registry
    // (credentialStatus is present) but this verifier has no DeDi client —
    // a revoked credential would verify as VALID here. Surface the skip as
    // a non-failing check row so operators and UIs can see the gap instead
    // of mistaking "not checked" for "checked and clean".
    checks.push({
      name: "revocation",
      passed: true,
      detail:
        "Credential declares credentialStatus but no DeDi registry is configured — " +
        "revocation was NOT checked. Configure `dedi` to enforce revocation.",
    });
  }

  // Key-status check (per-key registry; all DID methods).
  //
  // Looks up the signing key's status (`active` / `rotated` / `revoked`) in
  // the `opencred-key-registry`. A `revoked` key is fail-closed → top-level
  // `REVOKED`: a revoked key may be compromised, so no signature it produced
  // can be trusted. `active`/`rotated` pass (a clean rotation leaves old
  // credentials valid). The check degrades to a non-failing "not checked"
  // when the namespace can't be determined or DeDi is unreachable — see
  // `checkKeyStatus`.
  if (credentialForRevocationHash && config.dediClient) {
    const keyStatusCheck = await checkKeyStatus(credentialForRevocationHash, config.dediClient);
    checks.push(keyStatusCheck);
    if (!keyStatusCheck.passed) {
      return { code: "REVOKED", verified: false, checks };
    }
  }

  // Registry-anchor check (all DID methods, advisory).
  //
  // Surfaces the CORD-blockchain proof block DeDi attaches to record
  // lookup responses so verifier UIs can show "anchored on CORD by X"
  // provenance. Advisory: does not flip the headline `verified` boolean.
  // Anchor mismatches or missing proofs are surfaced as info rather than
  // rejection — the underlying VC signature is the authority on crypto
  // validity. On-chain CORD lookup is a follow-up.
  if (credentialForRevocationHash && config.dediClient) {
    const anchorCheck = await checkRegistryAnchor(credentialForRevocationHash, config.dediClient);
    checks.push(anchorCheck);
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
  if (isCanonicalizingProofFormat(format)) {
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
