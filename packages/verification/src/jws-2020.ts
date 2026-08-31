import { createVerify, verify as cryptoVerify, constants as cryptoConstants } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { computeJws2020VerifyData, buildJws2020SigningInput } from "@opencred/crypto";
import type { Jws2020ProofConfig } from "@opencred/crypto";
import { ContextNotFoundError } from "@opencred/vc-core";
import type { VerifiableCredential } from "@opencred/vc-core";
import type { DIDResolver } from "@opencred/did";
import { resolvePublicKeyFromVerificationMethod } from "./data-integrity.js";
import { ALLOWED_JWS_ALGORITHMS } from "./jws-proof.js";
import type { VerificationCheck } from "./types.js";

const PROOF_TYPE = "JsonWebSignature2020";

/**
 * Verify a JsonWebSignature2020 embedded proof:
 * `proof: { type: "JsonWebSignature2020", created, verificationMethod,
 * proofPurpose, jws: "<b64(header)>..<b64(signature)>" }`.
 *
 * The detached JWS uses RFC 7797 (`b64: false`): the signature covers
 * ASCII(BASE64URL(header) + ".") || verifyData, where verifyData is
 * SHA-256(URDNA2015(proof config)) || SHA-256(URDNA2015(document)).
 *
 * The signer's public key is resolved strictly from the DID document named
 * by `proof.verificationMethod` — there is no fallback to
 * credential-controlled key material.
 */
export async function verifyJws2020Proof(
  credential: VerifiableCredential,
  didResolver?: DIDResolver,
): Promise<VerificationCheck> {
  const proof = credential.proof;
  if (!proof) {
    return { name: "signature", passed: false, detail: "No proof found on credential" };
  }
  if (proof.type !== PROOF_TYPE) {
    return { name: "signature", passed: false, detail: `Unsupported proof type: ${proof.type}` };
  }

  const jws = proof["jws"];
  if (typeof jws !== "string" || jws.length === 0) {
    return { name: "signature", passed: false, detail: "Proof has no 'jws' value" };
  }

  // Detached compact JWS: header..signature (empty payload segment).
  const parts = jws.split(".");
  if (parts.length !== 3 || parts[1] !== "") {
    return {
      name: "signature",
      passed: false,
      detail:
        "Invalid detached JWS: expected '<header>..<signature>' with an empty payload segment",
    };
  }
  const [protectedHeaderB64, , signatureB64] = parts;

  let header: Record<string, unknown>;
  try {
    // JSON.parse can succeed with non-object values (null, numbers, strings);
    // `null` in particular would make the property accesses below throw.
    const parsed: unknown = JSON.parse(Buffer.from(protectedHeaderB64, "base64url").toString());
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {
        name: "signature",
        passed: false,
        detail: "JWS protected header is not a JSON object",
      };
    }
    header = parsed as Record<string, unknown>;
  } catch {
    return { name: "signature", passed: false, detail: "Failed to decode JWS protected header" };
  }

  const alg = header.alg as string | undefined;
  if (!alg || !(ALLOWED_JWS_ALGORITHMS as readonly string[]).includes(alg)) {
    return {
      name: "signature",
      passed: false,
      detail: `JWS 'alg' not permitted: ${String(alg)}. Allowed: ${ALLOWED_JWS_ALGORITHMS.join(", ")}`,
    };
  }

  // RFC 7797: the header MUST carry b64:false with "b64" listed in crit —
  // the signature is over the raw verify data, not a base64url payload.
  // Any crit member other than "b64" is an extension we cannot honor and
  // MUST be rejected per RFC 7515 §4.1.11.
  if (header.b64 !== false) {
    return {
      name: "signature",
      passed: false,
      detail: "JWS header must set 'b64': false for a detached JsonWebSignature2020 proof",
    };
  }
  const crit = header.crit;
  if (!Array.isArray(crit) || !crit.includes("b64") || crit.some((c) => c !== "b64")) {
    return {
      name: "signature",
      passed: false,
      detail: "JWS header 'crit' must be [\"b64\"]",
    };
  }

  const publicKey = await resolvePublicKeyFromVerificationMethod(
    proof.verificationMethod,
    didResolver,
  );
  if (!publicKey) {
    return {
      name: "signature",
      passed: false,
      detail: "Unable to resolve public key from verificationMethod",
    };
  }

  // Rebuild the proof config exactly as it was canonicalized at signing time.
  const proofConfig: Jws2020ProofConfig = {
    "@context": credential["@context"] as (string | Record<string, unknown>)[],
    type: PROOF_TYPE,
    created: proof.created,
    verificationMethod: proof.verificationMethod,
    proofPurpose: proof.proofPurpose,
  };
  if (proof.domain) {
    proofConfig.domain = proof.domain as string;
  }
  if (proof.challenge) {
    proofConfig.challenge = proof.challenge as string;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { proof: _proof, ...unsignedDoc } = credential;

  let signingInput: Uint8Array;
  try {
    const verifyData = await computeJws2020VerifyData(
      unsignedDoc as Record<string, unknown>,
      proofConfig,
    );
    signingInput = buildJws2020SigningInput(protectedHeaderB64, verifyData);
  } catch (error) {
    if (error instanceof ContextNotFoundError) {
      return {
        name: "signature",
        passed: false,
        detail: `Missing JSON-LD context: ${error.contextUrl}. Import this context before verifying, or ask the issuer to use VC-JWT format.`,
      };
    }
    return {
      name: "signature",
      passed: false,
      detail: `Canonicalization failed: ${error instanceof Error ? error.message : "unknown error"}`,
    };
  }

  // Buffer.from(str, "base64url") never throws — it silently skips invalid
  // characters — so enforce the alphabet explicitly. Without this, many
  // distinct `jws` strings would decode to the same signature bytes
  // (encoding malleability), inconsistent with the strict header checks.
  if (!/^[A-Za-z0-9_-]+$/.test(signatureB64)) {
    return { name: "signature", passed: false, detail: "JWS signature is not valid base64url" };
  }
  const signatureBytes = new Uint8Array(Buffer.from(signatureB64, "base64url"));
  if (signatureBytes.length === 0) {
    return { name: "signature", passed: false, detail: "Empty JWS signature" };
  }

  try {
    const verified = verifyJwsSignature(alg, signingInput, publicKey, signatureBytes);
    return verified
      ? { name: "signature", passed: true }
      : { name: "signature", passed: false, detail: "JWS signature verification failed" };
  } catch (error) {
    return {
      name: "signature",
      passed: false,
      detail: `JWS signature verification failed: ${error instanceof Error ? error.message : "unknown error"}`,
    };
  }
}

/**
 * Verify raw JWS signature bytes for the given JOSE algorithm.
 */
function verifyJwsSignature(
  alg: string,
  data: Uint8Array,
  publicKey: KeyObject,
  signature: Uint8Array,
): boolean {
  switch (alg) {
    case "ES256":
    case "ES384": {
      const verifier = createVerify(alg === "ES384" ? "SHA384" : "SHA256");
      verifier.update(data);
      return verifier.verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
    }
    case "EdDSA":
      return cryptoVerify(null, data, publicKey, signature);
    case "PS256":
      return cryptoVerify(
        "sha256",
        data,
        {
          key: publicKey,
          padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
        },
        signature,
      );
    default:
      // Unreachable: the alg allowlist above rejects everything else.
      return false;
  }
}
