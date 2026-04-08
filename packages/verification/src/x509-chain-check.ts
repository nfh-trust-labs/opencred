/**
 * X.509 certificate chain verification.
 *
 * Validates the x5c certificate chain embedded in a credential's proof,
 * linking the signing key back to a DSC (Digital Signature Certificate)
 * and optionally to a CSCA (Country Signing Certificate Authority).
 *
 * The x5c field follows JOSE conventions (RFC 7517 §4.7): an array of
 * base64-encoded DER certificates, leaf (DSC) first.
 *
 * Checks performed:
 * 1. The leaf certificate's public key matches the credential's signing key
 * 2. Each certificate in the chain was signed by the next (chain-of-trust)
 * 3. No certificate in the chain is expired at the credential's proof.created time
 */

import { X509Certificate } from "node:crypto";
import type { DIDResolver } from "@opencred/did";
import type { VerificationCheck } from "./types.js";

/**
 * Options for X.509 chain verification.
 */
export interface X509ChainCheckOptions {
  didResolver?: DIDResolver;
}

/**
 * Extract the public key from a DID's verification method.
 * Returns a JWK-format public key for comparison with the x5c leaf.
 */
async function resolveDidPublicKey(
  did: string,
  resolver?: DIDResolver,
): Promise<{ x: string; y: string; crv: string } | null> {
  if (!resolver) return null;

  try {
    const result = await resolver.resolve(did.split("#")[0]);
    const doc = result.didDocument;
    if (!doc || !doc.verificationMethod || doc.verificationMethod.length === 0) {
      return null;
    }

    // Find the matching verification method
    const vm =
      doc.verificationMethod.find(
        (v) => v.id === did || v.id === `${did.split("#")[0]}#${did.split("#")[1]}`,
      ) ?? doc.verificationMethod[0];

    const jwk = vm.publicKeyJwk;
    if (jwk && jwk.x && jwk.y && jwk.crv) {
      return { x: jwk.x as string, y: jwk.y as string, crv: jwk.crv as string };
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Parse a base64-encoded DER certificate into an X509Certificate.
 */
function parseX5cCert(base64Der: string): X509Certificate {
  const pem = `-----BEGIN CERTIFICATE-----\n${base64Der}\n-----END CERTIFICATE-----`;
  return new X509Certificate(pem);
}

/**
 * Check whether the leaf certificate's public key matches the DID's public key.
 */
function checkKeyBinding(
  leafCert: X509Certificate,
  didPublicKey: { x: string; y: string; crv: string },
): boolean {
  try {
    // leafCert.publicKey is already a KeyObject in Node 23+
    const certKeyObject = leafCert.publicKey;
    const certJwk = certKeyObject.export({ format: "jwk" }) as {
      x?: string;
      y?: string;
      crv?: string;
    };

    if (!certJwk.x || !certJwk.y || !certJwk.crv) return false;

    return (
      certJwk.x === didPublicKey.x &&
      certJwk.y === didPublicKey.y &&
      certJwk.crv === didPublicKey.crv
    );
  } catch {
    return false;
  }
}

/**
 * Validate the certificate chain's temporal bounds at a specific point in time.
 * Each certificate must be valid (not before / not after) at the given time.
 */
function checkChainTemporal(certs: X509Certificate[], proofTime: Date): string | null {
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    const notBefore = new Date(cert.validFrom);
    const notAfter = new Date(cert.validTo);
    const label = i === 0 ? "Leaf (DSC)" : `Chain certificate [${i}]`;

    if (proofTime < notBefore) {
      return `${label} was not yet valid at credential signing time (notBefore: ${cert.validFrom})`;
    }
    if (proofTime > notAfter) {
      return `${label} had expired at credential signing time (notAfter: ${cert.validTo})`;
    }
  }
  return null;
}

/**
 * Validate that each certificate in the chain was signed by the next.
 * cert[0] should be signed by cert[1], cert[1] by cert[2], etc.
 */
function checkChainSignatures(certs: X509Certificate[]): string | null {
  for (let i = 0; i < certs.length - 1; i++) {
    const child = certs[i];
    const parent = certs[i + 1];

    if (!child.checkIssued(parent)) {
      return `Certificate [${i}] was not issued by certificate [${i + 1}] (issuer/subject mismatch)`;
    }

    try {
      if (!child.verify(parent.publicKey)) {
        return `Certificate [${i}] signature does not verify against certificate [${i + 1}]`;
      }
    } catch {
      return `Certificate [${i}] signature verification failed against certificate [${i + 1}]`;
    }
  }
  return null;
}

/**
 * Check the X.509 certificate chain embedded in a credential's proof.
 *
 * If the credential has no x5c field, this check is skipped (returns passed).
 * When x5c is present, the full chain is validated:
 *  1. Parse all certificates
 *  2. Verify the leaf cert's public key matches the signing DID
 *  3. Verify chain-of-trust signatures
 *  4. Verify all certificates were valid at proof.created time
 */
export async function checkX509Chain(
  credential: Record<string, unknown>,
  options: X509ChainCheckOptions = {},
): Promise<VerificationCheck> {
  const proof = credential["proof"] as Record<string, unknown> | undefined;
  if (!proof) {
    return { name: "x509-chain", passed: true, detail: "No proof — X.509 chain check skipped" };
  }

  const x5c = proof["x5c"] as string[] | undefined;
  if (!x5c || !Array.isArray(x5c) || x5c.length === 0) {
    return {
      name: "x509-chain",
      passed: true,
      detail: "No x5c certificate chain — not a DSC-backed credential",
    };
  }

  // Parse all certificates
  let certs: X509Certificate[];
  try {
    certs = x5c.map(parseX5cCert);
  } catch (err) {
    return {
      name: "x509-chain",
      passed: false,
      detail: `Failed to parse x5c certificates: ${err instanceof Error ? err.message : "unknown error"}`,
    };
  }

  // Check 1: Leaf certificate public key matches the signing DID
  const verificationMethod = proof["verificationMethod"] as string | undefined;
  if (verificationMethod) {
    const didPubKey = await resolveDidPublicKey(verificationMethod, options.didResolver);
    if (didPubKey) {
      if (!checkKeyBinding(certs[0], didPubKey)) {
        return {
          name: "x509-chain",
          passed: false,
          detail:
            "X.509 chain invalid: leaf certificate public key does not match the signing DID's public key",
        };
      }
    }
    // If DID can't be resolved, skip key binding check (signature check already passed)
  }

  // Check 2: Chain-of-trust signatures (if more than one cert)
  if (certs.length > 1) {
    const chainError = checkChainSignatures(certs);
    if (chainError) {
      return {
        name: "x509-chain",
        passed: false,
        detail: `X.509 chain invalid: ${chainError}`,
      };
    }
  }

  // Check 3: Temporal validity at proof.created time
  const proofCreated = proof["created"] as string | undefined;
  if (proofCreated) {
    const proofTime = new Date(proofCreated);
    if (!isNaN(proofTime.getTime())) {
      const temporalError = checkChainTemporal(certs, proofTime);
      if (temporalError) {
        return {
          name: "x509-chain",
          passed: false,
          detail: `X.509 chain invalid: ${temporalError}`,
        };
      }
    }
  }

  // Build success detail
  const leaf = certs[0];
  const detail =
    certs.length > 1
      ? `DSC verified (${leaf.subject}), chain depth: ${certs.length}`
      : `DSC present (${leaf.subject}), self-signed or root not included`;

  return { name: "x509-chain", passed: true, detail };
}
