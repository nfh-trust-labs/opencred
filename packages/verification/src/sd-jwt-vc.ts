import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import * as jose from "jose";
import type { DIDResolver } from "@opencred/did";
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
export type Disclosure = [string, string, unknown];

/**
 * Parse an SD-JWT VC string into its components.
 * Format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~[<key-binding-jwt>]
 */
export function parseSdJwtVc(sdJwtVc: string): SdJwtVcComponents {
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
 * Decode a single disclosure from base64url to [salt, name, value].
 */
export function decodeDisclosure(disclosure: string): Disclosure {
  const json = Buffer.from(disclosure, "base64url").toString("utf-8");
  const parsed = JSON.parse(json) as unknown[];
  if (!Array.isArray(parsed) || parsed.length < 3) {
    throw new Error("Invalid disclosure format: expected [salt, name, value]");
  }
  return [String(parsed[0]), String(parsed[1]), parsed[2]];
}

/**
 * Process all disclosures and reconstruct the full claims.
 * Matches each disclosure's hash against _sd entries in the payload.
 */
export async function processDisclosures(
  payload: SdJwtVcPayload,
  disclosures: string[],
): Promise<Record<string, unknown>> {
  const result: Record<string, unknown> = { ...payload };

  const sdDigests = (payload["_sd"] as string[] | undefined) ?? [];
  const disclosureMap = new Map<string, Disclosure>();

  for (const d of disclosures) {
    const hash = await computeDisclosureDigest(d, payload["_sd_alg"] as string | undefined);
    disclosureMap.set(hash, decodeDisclosure(d));
  }

  for (const digest of sdDigests) {
    const disclosure = disclosureMap.get(digest);
    if (disclosure) {
      const [, name, value] = disclosure;
      result[name] = value;
    }
  }

  delete result["_sd"];
  delete result["_sd_alg"];

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

    // Verify sd_hash: the hash of the SD-JWT without the KB-JWT part
    const sdJwtWithoutKb = fullSdJwtVc.substring(0, fullSdJwtVc.lastIndexOf(keyBindingJwt));
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
