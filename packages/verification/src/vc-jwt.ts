import { createPublicKey, type KeyObject } from "node:crypto";
import * as jose from "jose";
import type { DIDResolver } from "@opencred/did";
import { VerificationError } from "@opencred/shared";
import { publicKeyFromMultibase } from "./key-utils.js";
import type { VerificationCheck } from "./types.js";

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
 * Verify a VC-JWT credential string.
 * Parses the JWT, resolves the issuer's public key via DID resolution,
 * and verifies the JWT signature.
 */
export async function verifyVcJwt(
  jwt: string,
  didResolver?: DIDResolver,
): Promise<{ check: VerificationCheck; payload: VcJwtPayload | null }> {
  try {
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

    await jose.jwtVerify(jwt, publicKey);

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
 */
export function extractVcJwtCredentialFields(payload: VcJwtPayload): {
  validFrom?: string;
  validUntil?: string;
  credentialStatus?: Record<string, unknown>;
  issuer?: string;
  credential?: Record<string, unknown>;
} {
  const vc = payload.vc ?? {};

  const validFrom = payload.nbf
    ? new Date(payload.nbf * 1000).toISOString()
    : (vc["validFrom"] as string | undefined);

  const validUntil = payload.exp
    ? new Date(payload.exp * 1000).toISOString()
    : (vc["validUntil"] as string | undefined);

  const credentialStatus = vc["credentialStatus"] as Record<string, unknown> | undefined;

  return {
    validFrom,
    validUntil,
    credentialStatus,
    issuer: payload.iss,
    credential: vc,
  };
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
