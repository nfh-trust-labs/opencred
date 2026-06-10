import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import * as jose from "jose";
import type { DIDResolver } from "@opencred/did";
import { assertJwtSize } from "@opencred/shared";
import { publicKeyFromMultibase } from "./key-utils.js";
import type { VerificationCheck } from "./types.js";

/** Allowed JWT signing algorithms — prevents algorithm confusion attacks. */
const ALLOWED_ALGORITHMS = ["ES256", "ES384", "ES512", "EdDSA"] as const;

/**
 * Decoded SD-JWT VC components.
 */
export interface SdJwtVcComponents {
  issuerJwt: string;
  disclosures: string[];
  keyBindingJwt?: string;
}

/**
 * Decoded SD-JWT VC payload with resolved disclosures.
 */
export interface SdJwtVcPayload {
  iss?: string;
  sub?: string;
  nbf?: number;
  exp?: number;
  iat?: number;
  vct?: string;
  [key: string]: unknown;
}

/**
 * Options for SD-JWT VC verification.
 */
export interface SdJwtVcVerifyOptions {
  /** Expected Verifiable Credential Type(s). If provided, the vct claim must match one of them. */
  expectedVct?: string | string[];
  /** Expected audience for Key Binding JWT verification. */
  expectedAudience?: string;
  /** Expected nonce for Key Binding JWT verification. */
  expectedNonce?: string;
}

/**
 * A decoded disclosure: [salt, claim_name, claim_value].
 */
/**
 * A decoded disclosure.
 *
 * Per draft-ietf-oauth-selective-disclosure-jwt:
 *   - Object/property disclosures are 3-tuples `[salt, name, value]`.
 *   - Array-element disclosures (§4.2.5) are 2-tuples `[salt, value]`.
 */
export type Disclosure = [string, string, unknown] | [string, unknown];

/**
 * Parse an SD-JWT VC string into its components.
 * Format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~[<key-binding-jwt>]
 */
export function parseSdJwtVc(sdJwtVc: string): SdJwtVcComponents {
  assertJwtSize(sdJwtVc);
  const parts = sdJwtVc.split("~");
  if (parts.length < 2) {
    throw new Error("Invalid SD-JWT VC format: must contain at least issuer JWT and one separator");
  }

  const issuerJwt = parts[0];
  const disclosures: string[] = [];
  let keyBindingJwt: string | undefined;

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    if (part === "") {
      continue;
    }
    if (i === parts.length - 1 && part.split(".").length === 3) {
      keyBindingJwt = part;
    } else {
      disclosures.push(part);
    }
  }

  return { issuerJwt, disclosures, keyBindingJwt };
}

/**
 * Decode a single disclosure from base64url.
 *
 * Returns either a 3-tuple `[salt, name, value]` (object/property
 * disclosure) or a 2-tuple `[salt, value]` (array-element disclosure
 * per §4.2.5). The caller is expected to dispatch on the tuple length
 * and reject disclosures used in the wrong position.
 */
export function decodeDisclosure(disclosure: string): Disclosure {
  const json = Buffer.from(disclosure, "base64url").toString("utf-8");
  const parsed = JSON.parse(json) as unknown[];
  if (!Array.isArray(parsed) || (parsed.length !== 2 && parsed.length !== 3)) {
    throw new Error("Invalid disclosure format: expected [salt, name, value] or [salt, value]");
  }
  if (parsed.length === 3) {
    return [String(parsed[0]), String(parsed[1]), parsed[2]];
  }
  return [String(parsed[0]), parsed[1]];
}

/**
 * Process all disclosures and reconstruct the full claims.
 *
 * Implements the SD-JWT draft (draft-ietf-oauth-selective-disclosure-jwt):
 *
 *  - §4.2.4: `_sd` entries may appear at any object nesting level. The
 *    walker recurses into every object value.
 *  - §4.2.5: array elements may be disclosed via the `{"...": "<digest>"}`
 *    object marker. When a matching disclosure is an array-element
 *    disclosure (`[salt, value]` — a 2-tuple, rather than the 3-tuple
 *    `[salt, name, value]` used for object claims), the marker is
 *    replaced with the disclosed value.
 *  - §7.1: any supplied disclosure that is never referenced by a digest
 *    MUST cause the verification to fail — unreferenced disclosures are
 *    an attempt to smuggle data past the verifier.
 *
 * Returns the reconstructed payload with every `_sd` and `_sd_alg` key
 * removed at every level.
 */
export async function processDisclosures(
  payload: SdJwtVcPayload,
  disclosures: string[],
): Promise<Record<string, unknown>> {
  const algorithm = payload["_sd_alg"] as string | undefined;

  // Build the digest → disclosure map once up-front.
  const disclosureMap = new Map<string, Disclosure>();
  for (const d of disclosures) {
    const hash = await computeDisclosureDigest(d, algorithm);
    disclosureMap.set(hash, decodeDisclosure(d));
  }

  // Track which digests were actually consumed so we can reject unused
  // disclosures per §7.1.
  const used = new Set<string>();

  const walk = (value: unknown): unknown => {
    if (Array.isArray(value)) {
      const next: unknown[] = [];
      for (const item of value) {
        // §4.2.5 — array-element disclosure marker.
        if (
          typeof item === "object" &&
          item !== null &&
          !Array.isArray(item) &&
          Object.keys(item as Record<string, unknown>).length === 1 &&
          typeof (item as Record<string, unknown>)["..."] === "string"
        ) {
          const digest = (item as Record<string, string>)["..."];
          const d = disclosureMap.get(digest);
          // Array disclosures are 2-tuples [salt, value]. Object
          // disclosures ([salt, name, value]) must NOT be used here.
          if (d && d.length === 2) {
            used.add(digest);
            next.push(walk(d[1]));
          }
          // Unmatched digest = decoy; drop silently per spec.
          continue;
        }
        next.push(walk(item));
      }
      return next;
    }

    if (typeof value === "object" && value !== null) {
      const obj = value as Record<string, unknown>;
      const out: Record<string, unknown> = {};

      for (const [k, v] of Object.entries(obj)) {
        if (k === "_sd" || k === "_sd_alg") continue; // stripped from output
        out[k] = walk(v);
      }

      // §4.2.4 — process object-level `_sd` digests at this level.
      const sdDigests = (obj["_sd"] as string[] | undefined) ?? [];
      for (const digest of sdDigests) {
        const d = disclosureMap.get(digest);
        if (!d) continue; // unmatched digest = decoy
        if (d.length !== 3) continue; // must be an object disclosure
        const [, name, disclosedValue] = d;
        used.add(digest);
        out[name] = walk(disclosedValue);
      }
      return out;
    }

    return value;
  };

  const result = walk(payload) as Record<string, unknown>;

  // §7.1 — reject when any supplied disclosure is unreferenced.
  if (used.size < disclosureMap.size) {
    const unused = disclosureMap.size - used.size;
    throw new Error(
      `SD-JWT VC verification rejected: ${unused} supplied disclosure(s) are not referenced by any _sd digest`,
    );
  }

  return result;
}

async function computeDisclosureDigest(disclosure: string, algorithm?: string): Promise<string> {
  const alg = algorithm ?? "sha-256";
  const encoder = new TextEncoder();
  const data = encoder.encode(disclosure);

  const hashBuffer = await globalThis.crypto.subtle.digest(
    alg === "sha-256" ? "SHA-256" : alg.toUpperCase(),
    data,
  );

  return Buffer.from(new Uint8Array(hashBuffer)).toString("base64url");
}

/**
 * Verify an SD-JWT VC credential string.
 *
 * Performs issuer JWT signature verification, vct claim validation (required per
 * SD-JWT VC spec), and Key Binding JWT verification when present.
 */
export async function verifySdJwtVc(
  sdJwtVc: string,
  didResolver?: DIDResolver,
  options?: SdJwtVcVerifyOptions,
): Promise<{
  check: VerificationCheck;
  payload: SdJwtVcPayload | null;
  resolvedClaims: Record<string, unknown> | null;
}> {
  try {
    const { issuerJwt, disclosures, keyBindingJwt } = parseSdJwtVc(sdJwtVc);

    const header = jose.decodeProtectedHeader(issuerJwt);
    if (!header.alg) {
      return {
        check: { name: "signature", passed: false, detail: "SD-JWT missing 'alg' header" },
        payload: null,
        resolvedClaims: null,
      };
    }

    const payload = jose.decodeJwt(issuerJwt) as SdJwtVcPayload;
    if (!payload.iss) {
      return {
        check: { name: "signature", passed: false, detail: "SD-JWT missing 'iss' claim" },
        payload: null,
        resolvedClaims: null,
      };
    }

    // #130: Validate vct claim (required per SD-JWT VC spec)
    const vctCheck = validateVctClaim(payload, options?.expectedVct);
    if (!vctCheck.passed) {
      return {
        check: vctCheck,
        payload,
        resolvedClaims: null,
      };
    }

    const publicKey = await resolveIssuerKeyForSdJwt(payload.iss, header, didResolver);
    if (!publicKey) {
      return {
        check: {
          name: "signature",
          passed: false,
          detail: `Unable to resolve public key for issuer: ${payload.iss}`,
        },
        payload,
        resolvedClaims: null,
      };
    }

    await jose.jwtVerify(issuerJwt, publicKey, {
      algorithms: ALLOWED_ALGORITHMS as unknown as string[],
    });

    // #129: Verify Key Binding JWT if present
    if (keyBindingJwt) {
      const kbCheck = await verifyKeyBindingJwt(keyBindingJwt, payload, sdJwtVc, options);
      if (!kbCheck.passed) {
        return {
          check: kbCheck,
          payload,
          resolvedClaims: null,
        };
      }
    }

    const resolvedClaims = await processDisclosures(payload, disclosures);

    return {
      check: { name: "signature", passed: true },
      payload,
      resolvedClaims,
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : "SD-JWT VC verification failed";
    return {
      check: { name: "signature", passed: false, detail },
      payload: null,
      resolvedClaims: null,
    };
  }
}

/**
 * Validate the vct (Verifiable Credential Type) claim per SD-JWT VC spec.
 * The vct claim is REQUIRED in SD-JWT VC payloads.
 */
function validateVctClaim(
  payload: SdJwtVcPayload,
  expectedVct?: string | string[],
): VerificationCheck {
  if (!payload.vct || typeof payload.vct !== "string") {
    return {
      name: "vct",
      passed: false,
      detail: "SD-JWT VC missing required 'vct' claim",
    };
  }

  if (expectedVct !== undefined) {
    const expected = Array.isArray(expectedVct) ? expectedVct : [expectedVct];
    if (!expected.includes(payload.vct)) {
      return {
        name: "vct",
        passed: false,
        detail: `SD-JWT VC 'vct' claim '${payload.vct}' does not match expected type(s): ${expected.join(", ")}`,
      };
    }
  }

  return { name: "vct", passed: true };
}

/**
 * Verify the Key Binding JWT per SD-JWT VC specification.
 * The KB-JWT proves that the presenter holds the key bound to the credential.
 */
async function verifyKeyBindingJwt(
  keyBindingJwt: string,
  issuerPayload: SdJwtVcPayload,
  fullSdJwtVc: string,
  options?: SdJwtVcVerifyOptions,
): Promise<VerificationCheck> {
  try {
    // The cnf (confirmation) claim holds the holder's public key
    const cnf = issuerPayload["cnf"] as { jwk?: jose.JWK } | undefined;
    if (!cnf?.jwk) {
      return {
        name: "key_binding",
        passed: false,
        detail: "SD-JWT VC missing 'cnf' claim with holder public key for Key Binding verification",
      };
    }

    // Verify KB-JWT header has typ: "kb+jwt"
    const kbHeader = jose.decodeProtectedHeader(keyBindingJwt);
    if (kbHeader.typ !== "kb+jwt") {
      return {
        name: "key_binding",
        passed: false,
        detail: `Key Binding JWT 'typ' header must be 'kb+jwt', got '${kbHeader.typ ?? "undefined"}'`,
      };
    }

    // Import the holder's public key from the cnf claim
    const holderKey = await jose.importJWK(cnf.jwk, kbHeader.alg);

    // Verify the KB-JWT signature
    const { payload: kbPayload } = await jose.jwtVerify(keyBindingJwt, holderKey, {
      algorithms: ALLOWED_ALGORITHMS as unknown as string[],
    });

    // Verify sd_hash: the hash of the SD-JWT without the KB-JWT part.
    // Per SD-JWT §4.3 the serialization is
    // `<issuer-jwt>~<disclosure>~...~<kb-jwt>`, so the KB-JWT is exactly
    // the segment after the LAST `~`. Cutting at that structural boundary
    // (rather than string-searching for the KB-JWT's own bytes) cannot be
    // confused by a crafted disclosure that happens to contain the KB-JWT
    // as a substring.
    const sdJwtWithoutKb = fullSdJwtVc.substring(0, fullSdJwtVc.lastIndexOf("~") + 1);
    const sdAlg = issuerPayload["_sd_alg"] as string | undefined;
    const expectedSdHash = computeSdHash(sdJwtWithoutKb, sdAlg);
    if (kbPayload["sd_hash"] !== expectedSdHash) {
      return {
        name: "key_binding",
        passed: false,
        detail: "Key Binding JWT 'sd_hash' does not match the SD-JWT content",
      };
    }

    // Verify audience if expected
    if (options?.expectedAudience) {
      const aud = kbPayload.aud;
      const audMatch = Array.isArray(aud)
        ? aud.includes(options.expectedAudience)
        : aud === options.expectedAudience;
      if (!audMatch) {
        return {
          name: "key_binding",
          passed: false,
          detail: `Key Binding JWT 'aud' does not match expected audience '${options.expectedAudience}'`,
        };
      }
    }

    // Verify nonce if expected
    if (options?.expectedNonce && kbPayload["nonce"] !== options.expectedNonce) {
      return {
        name: "key_binding",
        passed: false,
        detail: "Key Binding JWT 'nonce' does not match expected nonce",
      };
    }

    return { name: "key_binding", passed: true };
  } catch (error) {
    const detail =
      error instanceof Error
        ? `Key Binding JWT verification failed: ${error.message}`
        : "Key Binding JWT verification failed";
    return { name: "key_binding", passed: false, detail };
  }
}

/**
 * Compute the sd_hash for Key Binding JWT verification.
 * Hashes the SD-JWT string (without KB-JWT) using the _sd_alg algorithm.
 */
function computeSdHash(sdJwtWithoutKb: string, algorithm?: string): string {
  const alg = algorithm ?? "sha-256";
  const nodeAlg = alg === "sha-256" ? "sha256" : alg.replace(/-/g, "");
  const hash = createHash(nodeAlg).update(sdJwtWithoutKb, "ascii").digest();
  return Buffer.from(hash).toString("base64url");
}

/**
 * Extract credential fields from an SD-JWT VC payload.
 */
export function extractSdJwtVcCredentialFields(
  payload: SdJwtVcPayload,
  resolvedClaims: Record<string, unknown>,
): {
  validFrom?: string;
  validUntil?: string;
  credentialStatus?: Record<string, unknown>;
  issuer?: string;
} {
  const validFrom = payload.nbf
    ? new Date(payload.nbf * 1000).toISOString()
    : (resolvedClaims["validFrom"] as string | undefined);

  const validUntil = payload.exp
    ? new Date(payload.exp * 1000).toISOString()
    : (resolvedClaims["validUntil"] as string | undefined);

  const credentialStatus =
    (resolvedClaims["credentialStatus"] as Record<string, unknown> | undefined) ??
    (payload["status"] as Record<string, unknown> | undefined);

  return {
    validFrom,
    validUntil,
    credentialStatus,
    issuer: payload.iss,
  };
}

async function resolveIssuerKeyForSdJwt(
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
