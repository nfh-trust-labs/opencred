import { createSign, constants as cryptoConstants, sign as cryptoSign } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import { JWS_2020_V1_CONTEXT } from "@opencred/vc-core";
import type { UnsignedCredential, VerifiableCredential, Proof } from "@opencred/vc-core";
import { canonicalize } from "./data-integrity.js";
import { sha256 } from "./hash.js";
import { signingAlgorithmToJwsAlg } from "./alg-mapping.js";
import type { SigningAlgorithm, SigningKey, ProofOptions } from "./types.js";

const PROOF_TYPE = "JsonWebSignature2020" as const;

/**
 * Proof configuration for a JsonWebSignature2020 embedded proof.
 *
 * Unlike DataIntegrityProof there is no `cryptosuite` — the algorithm is
 * carried in the detached JWS protected header instead.
 */
export interface Jws2020ProofConfig {
  "@context": (string | Record<string, unknown>)[];
  type: typeof PROOF_TYPE;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  domain?: string;
  challenge?: string;
}

/**
 * A prepared JsonWebSignature2020 proof for two-phase (Interface) signing.
 */
export interface Jws2020PreparedProof {
  /**
   * The JWS signing input per RFC 7797 (`b64: false`):
   * ASCII(BASE64URL(header) + ".") || verifyData, where verifyData is
   * SHA-256(canonicalized proof config) || SHA-256(canonicalized document).
   */
  dataToSign: Uint8Array;
  /** The proof configuration (embedded into the credential once signed). */
  proofConfig: Jws2020ProofConfig;
  /** The base64url-encoded protected header — the first segment of the detached JWS. */
  protectedHeaderB64: string;
  /**
   * The document that was actually signed. This is the input credential with
   * the JWS-2020 suite context appended to `@context` when it was missing —
   * pass THIS document to `completeJws2020Proof`, not the original input,
   * or the issued credential will not match the signed bytes.
   */
  document: UnsignedCredential;
}

/**
 * Return a copy of the credential whose `@context` includes the JWS-2020
 * suite context (required so `JsonWebSignature2020` and the proof terms are
 * defined under strict canonicalization). Returns the input unchanged when
 * the context is already present.
 */
export function ensureJws2020Context(unsignedVC: UnsignedCredential): UnsignedCredential {
  const context = unsignedVC["@context"];
  if (!Array.isArray(context)) {
    throw new CryptoError("Credential @context must be an array");
  }
  if (context.includes(JWS_2020_V1_CONTEXT)) {
    return unsignedVC;
  }
  return { ...unsignedVC, "@context": [...context, JWS_2020_V1_CONTEXT] };
}

/**
 * Build the RFC 7797 protected header for a JsonWebSignature2020 proof.
 *
 * Per the JSON Web Signature 2020 suite the header is exactly
 * `{ alg, b64: false, crit: ["b64"] }` — the key reference lives in the
 * proof's `verificationMethod`, not in a `kid` header parameter.
 */
export function jws2020ProtectedHeader(algorithm: SigningAlgorithm): {
  alg: string;
  b64: false;
  crit: ["b64"];
} {
  return { alg: signingAlgorithmToJwsAlg(algorithm), b64: false, crit: ["b64"] };
}

/**
 * Prepare a JsonWebSignature2020 proof for signing (phase 1 of two-phase
 * signing; also used internally by `signCredentialJws2020`).
 *
 * Computes the verify data per the JSON Web Signature 2020 suite —
 * SHA-256(URDNA2015(proofConfig)) || SHA-256(URDNA2015(document)) — and
 * wraps it in the RFC 7797 detached signing input
 * `ASCII(BASE64URL(header) + ".") || verifyData`.
 *
 * @throws {CryptoError} if canonicalization fails (e.g. a term is not
 *   defined in the loaded JSON-LD contexts — strict mode is always on).
 */
export async function prepareJws2020Proof(
  unsignedVC: UnsignedCredential,
  algorithm: SigningAlgorithm,
  options: ProofOptions,
): Promise<Jws2020PreparedProof> {
  if (!options.verificationMethod) {
    throw new CryptoError("verificationMethod is required");
  }
  if (!options.proofPurpose) {
    throw new CryptoError("proofPurpose is required");
  }

  const document = ensureJws2020Context(unsignedVC);

  const proofConfig: Jws2020ProofConfig = {
    "@context": document["@context"] as (string | Record<string, unknown>)[],
    type: PROOF_TYPE,
    created: new Date().toISOString(),
    verificationMethod: options.verificationMethod,
    proofPurpose: options.proofPurpose,
  };
  if (options.domain) {
    proofConfig.domain = options.domain;
  }
  if (options.challenge) {
    proofConfig.challenge = options.challenge;
  }

  const header = jws2020ProtectedHeader(algorithm);
  const protectedHeaderB64 = Buffer.from(JSON.stringify(header)).toString("base64url");

  try {
    const verifyData = await computeJws2020VerifyData(
      document as unknown as Record<string, unknown>,
      proofConfig,
    );
    const dataToSign = buildJws2020SigningInput(protectedHeaderB64, verifyData);
    return { dataToSign, proofConfig, protectedHeaderB64, document };
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Failed to prepare JWS-2020 proof: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Compute the JsonWebSignature2020 verify data:
 * SHA-256(canonicalized proof config) || SHA-256(canonicalized document).
 *
 * The suite always uses SHA-256 for the verify data, independent of the JWS
 * `alg` — the signature algorithm applies its own digest on top.
 */
export async function computeJws2020VerifyData(
  document: Record<string, unknown>,
  proofConfig: Jws2020ProofConfig,
): Promise<Uint8Array> {
  const canonicalProofConfig = await canonicalize(
    proofConfig as unknown as Record<string, unknown>,
  );
  const canonicalDocument = await canonicalize(document);
  const proofConfigHash = sha256(canonicalProofConfig);
  const documentHash = sha256(canonicalDocument);
  const result = new Uint8Array(proofConfigHash.length + documentHash.length);
  result.set(proofConfigHash, 0);
  result.set(documentHash, proofConfigHash.length);
  return result;
}

/**
 * Assemble the RFC 7797 signing input for a detached (`b64: false`) JWS:
 * ASCII(BASE64URL(header) + ".") || payloadBytes.
 */
export function buildJws2020SigningInput(
  protectedHeaderB64: string,
  payloadBytes: Uint8Array,
): Uint8Array {
  const prefix = Buffer.from(`${protectedHeaderB64}.`, "ascii");
  const input = new Uint8Array(prefix.length + payloadBytes.length);
  input.set(prefix, 0);
  input.set(payloadBytes, prefix.length);
  return input;
}

/**
 * Complete a JsonWebSignature2020 proof with the signature bytes
 * (phase 2 of two-phase signing).
 *
 * The signature bytes must be in JWS format for the algorithm: raw r||s for
 * ECDSA (64 bytes P-256 / 96 bytes P-384), raw 64 bytes for Ed25519, and the
 * PSS signature for RSA.
 *
 * @returns The `prepared.document` (context-augmented credential) with the
 *   embedded proof attached: `{ type, created, verificationMethod,
 *   proofPurpose, jws: "<header>..<signature>" }`.
 */
export function completeJws2020Proof(
  prepared: Jws2020PreparedProof,
  signatureBytes: Uint8Array,
): VerifiableCredential {
  if (signatureBytes.length === 0) {
    throw new CryptoError("Signature bytes must not be empty");
  }
  const signatureB64 = Buffer.from(signatureBytes).toString("base64url");
  const jws = `${prepared.protectedHeaderB64}..${signatureB64}`;

  const proof: Proof = {
    type: prepared.proofConfig.type,
    created: prepared.proofConfig.created,
    verificationMethod: prepared.proofConfig.verificationMethod,
    proofPurpose: prepared.proofConfig.proofPurpose,
    jws,
  } as unknown as Proof;

  if (prepared.proofConfig.domain) {
    proof.domain = prepared.proofConfig.domain;
  }
  if (prepared.proofConfig.challenge) {
    proof.challenge = prepared.proofConfig.challenge;
  }

  return { ...prepared.document, proof };
}

/**
 * Sign a credential with a JsonWebSignature2020 embedded proof
 * (Delegated Signing — the private key is available in-process and never
 * transmitted).
 *
 * Works with all supported key algorithms: P-256 (ES256), P-384 (ES384),
 * Ed25519 (EdDSA), and RSA (PS256).
 */
export async function signCredentialJws2020(
  unsignedVC: UnsignedCredential,
  signingKey: SigningKey,
  options: ProofOptions,
): Promise<VerifiableCredential> {
  const prepared = await prepareJws2020Proof(unsignedVC, signingKey.algorithm, {
    ...options,
    verificationMethod: options.verificationMethod || signingKey.id,
  });

  try {
    const signatureBytes = signJwsBytes(prepared.dataToSign, signingKey);
    return completeJws2020Proof(prepared, signatureBytes);
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `JWS-2020 signing failed: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Sign raw bytes in JWS signature format for the key's algorithm.
 */
function signJwsBytes(data: Uint8Array, signingKey: SigningKey): Uint8Array {
  switch (signingKey.algorithm) {
    case "P-256":
    case "P-384": {
      const signer = createSign(signingKey.algorithm === "P-384" ? "SHA384" : "SHA256");
      signer.update(data);
      return new Uint8Array(signer.sign({ key: signingKey.privateKey, dsaEncoding: "ieee-p1363" }));
    }
    case "Ed25519":
      return new Uint8Array(cryptoSign(null, data, signingKey.privateKey));
    case "RSA-2048":
    case "RSA-3072":
    case "RSA-4096":
      // PS256 — RSASSA-PSS with SHA-256, salt length = digest length.
      return new Uint8Array(
        cryptoSign("sha256", data, {
          key: signingKey.privateKey,
          padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
        }),
      );
    default:
      throw new CryptoError(`Unsupported algorithm for JWS-2020: ${signingKey.algorithm}`);
  }
}
