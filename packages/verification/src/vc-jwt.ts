import { createPublicKey, type KeyObject } from "node:crypto";
import * as jose from "jose";
import type { DIDResolver } from "@opencred/did";
import { VerificationError, assertJwtSize } from "@opencred/shared";
import { publicKeyFromMultibase } from "./key-utils.js";
import type { VerificationCheck } from "./types.js";

/** Allowed JWT signing algorithms — prevents algorithm confusion attacks. */
const ALLOWED_ALGORITHMS = ["ES256", "ES384", "ES512", "EdDSA"] as const;

/**
 * Decoded VC-JWT payload with extracted credential data.
 */
export interface VcJwtPayload {
  iss?: string;
  sub?: string;
  nbf?: number;
  exp?: number;
  jti?: string;
  vc?: Record<string, unknown>;
}

/**
 * Decode the payload of a compact JWT **without verifying the signature**.
 *
 * Intended for offline rendering paths (e.g. the credential packager
 * extracting display claims for a PDF certificate) where the integrity
 * guarantee comes from preserving the original token byte-for-byte
 * elsewhere — never use this as a replacement for `verifyVcJwt`.
 *
 * Re-exported via the package index so other workspace packages don't
 * have to take a direct dependency on `jose`.
 *
 * @throws if the input isn't parseable as a compact JWT.
 */
export function decodeJwtPayloadUnsafe(jwt: string): Record<string, unknown> {
  assertJwtSize(jwt);
  return jose.decodeJwt(jwt) as Record<string, unknown>;
}

/**
 * Is this object the OpenCred VC-JWT *envelope* — a JSON-LD credential
 * wrapping its compact token as `proof: { type: "JsonWebSignature2020",
 * jwt }`? This is the canonical shape both the Desktop Client and the
 * Docker image emit for `proofFormat: "vc-jwt"`, and what their PDF /
 * QR / JSON exports embed.
 */
export function isJwsEnvelope(input: unknown): boolean {
  if (typeof input !== "object" || input === null) return false;
  const proof = (input as Record<string, unknown>)["proof"];
  if (typeof proof !== "object" || proof === null) return false;
  const p = proof as Record<string, unknown>;
  return p["type"] === "JsonWebSignature2020" && typeof p["jwt"] === "string";
}

/** JSON.stringify with recursively sorted object keys — stable comparison form. */
function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

function isoToUnixFloor(iso: unknown): number | undefined {
  if (typeof iso !== "string") return undefined;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? undefined : Math.floor(ms / 1000);
}

/**
 * Cross-validate a VC-JWT envelope's outer JSON against the (still
 * unverified) inner token's payload.
 *
 * The envelope's display fields carry NO signature of their own — only the
 * inner JWT is signed. Without this check, an attacker could keep a valid
 * inner token and swap the outer `credentialSubject` (what UIs render),
 * and the credential would still verify. The comparison mirrors the
 * issuance-side claim lifting in `@opencred/crypto`'s `buildVcJwtClaims`:
 *
 *  - `issuer` ↔ `iss`, `id` ↔ `jti`, `credentialSubject.id` ↔ `sub`,
 *    `validFrom`/`issuanceDate` ↔ `nbf`, `validUntil`/`expirationDate` ↔ `exp`
 *  - everything else (minus `proof`) must deep-equal the `vc` claim.
 *
 * Decoding the payload without signature verification is sound here: the
 * caller verifies the inner JWT's signature immediately afterwards, so a
 * forged payload that passes this comparison still fails overall.
 */
export function checkJwsEnvelopeConsistency(
  envelope: Record<string, unknown>,
  jwt: string,
): VerificationCheck {
  const name = "envelope-consistency";
  let payload: Record<string, unknown>;
  try {
    payload = decodeJwtPayloadUnsafe(jwt);
  } catch (err) {
    return {
      name,
      passed: false,
      detail: `Embedded proof.jwt could not be decoded: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const mismatches: string[] = [];

  // Lifted registered claims.
  const issuer = envelope["issuer"];
  const issuerId =
    typeof issuer === "string"
      ? issuer
      : ((issuer as { id?: string } | undefined)?.id ?? undefined);
  if (issuerId !== (payload["iss"] as string | undefined)) {
    mismatches.push("issuer does not match JWT iss");
  }
  if (envelope["id"] !== payload["jti"] && (envelope["id"] ?? payload["jti"]) !== undefined) {
    mismatches.push("id does not match JWT jti");
  }
  const subjectId = (envelope["credentialSubject"] as Record<string, unknown> | undefined)?.["id"];
  if (subjectId !== payload["sub"] && (subjectId ?? payload["sub"]) !== undefined) {
    mismatches.push("credentialSubject.id does not match JWT sub");
  }
  const envNbf = isoToUnixFloor(envelope["validFrom"] ?? envelope["issuanceDate"]);
  if (envNbf !== (payload["nbf"] as number | undefined)) {
    mismatches.push("validFrom does not match JWT nbf");
  }
  const envExp = isoToUnixFloor(envelope["validUntil"] ?? envelope["expirationDate"]);
  if (envExp !== (payload["exp"] as number | undefined)) {
    mismatches.push("validUntil does not match JWT exp");
  }

  // Remainder of the credential vs the `vc` claim — mirror the strip list
  // in buildVcJwtClaims.
  const stripped: Record<string, unknown> = { ...envelope };
  delete stripped["proof"];
  delete stripped["issuer"];
  delete stripped["validFrom"];
  delete stripped["validUntil"];
  delete stripped["issuanceDate"];
  delete stripped["expirationDate"];
  if (stripped["credentialSubject"] && typeof stripped["credentialSubject"] === "object") {
    const subjectCopy = { ...(stripped["credentialSubject"] as Record<string, unknown>) };
    delete subjectCopy["id"];
    stripped["credentialSubject"] = subjectCopy;
  }
  const vcClaim = payload["vc"];
  if (stableStringify(stripped) !== stableStringify(vcClaim ?? {})) {
    mismatches.push("credential body does not match the signed vc claim");
  }

  if (mismatches.length > 0) {
    return {
      name,
      passed: false,
      detail: `Envelope does not match its signed JWT payload: ${mismatches.join("; ")}`,
    };
  }
  return { name, passed: true };
}

/**
 * Verify a VC-JWT credential string.
 * Parses the JWT, resolves the issuer's public key via DID resolution,
 * and verifies the JWT signature.
 */
export async function verifyVcJwt(
  jwt: string,
  didResolver?: DIDResolver,
): Promise<{ check: VerificationCheck; payload: VcJwtPayload | null }> {
  try {
    assertJwtSize(jwt);

    const header = jose.decodeProtectedHeader(jwt);
    if (!header.alg) {
      return {
        check: { name: "signature", passed: false, detail: "JWT missing 'alg' header" },
        payload: null,
      };
    }

    const payload = jose.decodeJwt(jwt) as VcJwtPayload;
    if (!payload.iss) {
      return {
        check: { name: "signature", passed: false, detail: "JWT missing 'iss' claim" },
        payload: null,
      };
    }

    const publicKey = await resolveIssuerKey(payload.iss, header, didResolver);
    if (!publicKey) {
      return {
        check: {
          name: "signature",
          passed: false,
          detail: `Unable to resolve public key for issuer: ${payload.iss}`,
        },
        payload,
      };
    }

    try {
      await jose.jwtVerify(jwt, publicKey, {
        algorithms: ALLOWED_ALGORITHMS as unknown as string[],
      });
    } catch (error) {
      // jose validates the signature BEFORE evaluating registered claims,
      // so an exp/nbf claim failure means the signature itself is sound.
      // Let the dedicated date check downstream classify it (EXPIRED /
      // not-yet-valid) — otherwise an expired vc-jwt surfaces as INVALID
      // while an expired data-integrity credential surfaces as EXPIRED,
      // and relying parties can't branch on the result code consistently.
      const code = (error as { code?: string }).code;
      const claim = (error as { claim?: string }).claim;
      const isDateClaimFailure =
        code === "ERR_JWT_EXPIRED" ||
        (code === "ERR_JWT_CLAIM_VALIDATION_FAILED" && (claim === "nbf" || claim === "exp"));
      if (!isDateClaimFailure) throw error;
    }

    return {
      check: { name: "signature", passed: true },
      payload,
    };
  } catch (error) {
    if (error instanceof VerificationError) {
      return {
        check: { name: "signature", passed: false, detail: error.message },
        payload: null,
      };
    }
    const detail = error instanceof Error ? error.message : "JWT verification failed";
    return {
      check: { name: "signature", passed: false, detail },
      payload: null,
    };
  }
}

/**
 * Extract credential fields from a VC-JWT payload.
 *
 * Supports two payload layouts:
 * - **DM 1.1**: credential data is nested under `payload.vc`
 * - **DM 2.0**: credential fields (`type`, `credentialSubject`, `validFrom`,
 *   `validUntil`, `credentialStatus`) live directly on the payload
 */
export function extractVcJwtCredentialFields(payload: VcJwtPayload): {
  validFrom?: string;
  validUntil?: string;
  credentialStatus?: Record<string, unknown>;
  issuer?: string;
  credential?: Record<string, unknown>;
} {
  // DM 1.1: credential nested under `vc` claim
  // DM 2.0: credential fields directly on the payload
  const isDm11 = payload.vc !== undefined;
  const source: Record<string, unknown> = isDm11
    ? payload.vc!
    : (payload as Record<string, unknown>);

  const validFrom = payload.nbf
    ? new Date(payload.nbf * 1000).toISOString()
    : (source["validFrom"] as string | undefined);

  const validUntil = payload.exp
    ? new Date(payload.exp * 1000).toISOString()
    : (source["validUntil"] as string | undefined);

  const credentialStatus = source["credentialStatus"] as Record<string, unknown> | undefined;

  return {
    validFrom,
    validUntil,
    credentialStatus,
    issuer: payload.iss,
    credential: isDm11 ? payload.vc! : (payload as unknown as Record<string, unknown>),
  };
}

/**
 * Cross-validate JWT-level claims (jti, sub) against the VC fields.
 *
 * Per the VC-JWT specification:
 * - `jti` MUST equal the credential `id` (if both are present)
 * - `sub` MUST equal `credentialSubject.id` (if both are present)
 *
 * Applies to both payload layouts: DM 1.1 (credential nested under `vc`)
 * and DM 2.0 (credential fields directly on the payload). Without the
 * DM 2.0 path a flat-layout token could pair a `sub` the relying party
 * trusts with a swapped `credentialSubject`.
 *
 * Returns a list of mismatches (empty if consistent).
 */
export function crossValidateVcJwtClaims(payload: VcJwtPayload): string[] {
  const errors: string[] = [];

  // DM 1.1: credential nested under `vc`; DM 2.0: flat payload.
  const isDm11 = payload.vc !== undefined;
  const source: Record<string, unknown> = isDm11
    ? payload.vc!
    : (payload as Record<string, unknown>);
  const idLabel = isDm11 ? "vc.id" : "credential id";
  const subjectLabel = isDm11 ? "vc.credentialSubject.id" : "credentialSubject.id";

  // In the flat DM 2.0 layout the credential `id` and the JWT `jti` are the
  // same top-level field only when serialized as a registered claim;
  // issuers that set both `id` and `jti` must keep them consistent.
  const vcId = source["id"] as string | undefined;
  if (payload.jti && vcId && payload.jti !== vcId) {
    errors.push(`JWT jti claim "${payload.jti}" does not match ${idLabel} "${vcId}"`);
  }

  const credentialSubject = source["credentialSubject"] as Record<string, unknown> | undefined;
  const subjectId = credentialSubject?.["id"] as string | undefined;
  if (payload.sub && subjectId && payload.sub !== subjectId) {
    errors.push(`JWT sub claim "${payload.sub}" does not match ${subjectLabel} "${subjectId}"`);
  }

  return errors;
}

async function resolveIssuerKey(
  issuer: string,
  header: jose.ProtectedHeaderParameters,
  didResolver?: DIDResolver,
): Promise<KeyObject | null> {
  if (!didResolver || !issuer.startsWith("did:")) {
    return null;
  }

  try {
    const resolution = await didResolver.resolve(issuer);
    if (!resolution.didDocument?.verificationMethod?.length) {
      return null;
    }

    const vms = resolution.didDocument.verificationMethod;
    const targetId = header.kid;
    const vm = targetId ? vms.find((m) => m.id === targetId) : vms[0];
    if (!vm) {
      return null;
    }

    if (vm.publicKeyJwk) {
      return createPublicKey({ key: vm.publicKeyJwk, format: "jwk" });
    }

    if (vm.publicKeyMultibase) {
      return publicKeyFromMultibase(vm.publicKeyMultibase);
    }

    return null;
  } catch {
    return null;
  }
}
