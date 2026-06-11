/**
 * EdDSA Data Integrity proofs using the eddsa-rdfc-2022 cryptosuite.
 *
 * Same RDFC-1.0 canonicalization and SHA-256 hashing as ecdsa-rdfc-2019,
 * but with Ed25519 signing (64-byte signature, no DER conversion).
 *
 * W3C spec: https://www.w3.org/TR/vc-di-eddsa/
 */

import { sign, verify, type KeyObject } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import type { UnsignedCredential, VerifiableCredential, Proof } from "@opencred/vc-core";
import {
  computeSigningInput,
  multibaseEncode,
  multibaseDecode,
  buildProofConfig,
} from "./data-integrity.js";
import type {
  ProofOptions,
  PreparedProof,
  SigningKey,
  VerificationResult,
  VerifyOptions,
  ProofConfig,
} from "./types.js";

const EDDSA_CRYPTOSUITE = "eddsa-rdfc-2022" as const;
const ED25519_SIGNATURE_LENGTH = 64;

/**
 * Prepare an EdDSA Data Integrity proof for external (Interface) signing.
 *
 * Phase 1 of two-phase signing: computes the data that needs to be signed.
 * The caller signs externally and calls `completeEdDsaProof()` to assemble.
 */
export async function prepareEdDsaProof(
  unsignedVC: UnsignedCredential,
  options: ProofOptions,
): Promise<PreparedProof> {
  if (!options.verificationMethod) {
    throw new CryptoError("verificationMethod is required");
  }
  if (!options.proofPurpose) {
    throw new CryptoError("proofPurpose is required");
  }

  try {
    const proofConfig = buildProofConfig(unsignedVC, options, EDDSA_CRYPTOSUITE);
    const document = unsignedVC as unknown as Record<string, unknown>;
    const dataToSign = await computeSigningInput(document, proofConfig, "sha256");

    return { dataToSign, proofConfig };
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Failed to prepare EdDSA proof: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Complete an EdDSA Data Integrity proof with an externally-produced signature.
 *
 * Phase 2 of two-phase signing: assembles the final VerifiableCredential.
 *
 * @param credential — The unsigned credential.
 * @param proofConfig — The proof configuration from `prepareEdDsaProof()`.
 * @param signatureBytes — The raw Ed25519 signature bytes (64 bytes).
 */
export function completeEdDsaProof(
  credential: UnsignedCredential,
  proofConfig: ProofConfig,
  signatureBytes: Uint8Array,
): VerifiableCredential {
  if (signatureBytes.length !== ED25519_SIGNATURE_LENGTH) {
    throw new CryptoError(
      `EdDSA signature must be exactly ${ED25519_SIGNATURE_LENGTH} bytes (Ed25519), got ${signatureBytes.length}`,
    );
  }

  const proofValue = multibaseEncode(signatureBytes);

  const proof: Proof = {
    type: proofConfig.type,
    cryptosuite: proofConfig.cryptosuite,
    created: proofConfig.created,
    verificationMethod: proofConfig.verificationMethod,
    proofPurpose: proofConfig.proofPurpose,
    proofValue,
  };

  if (proofConfig.domain) {
    proof.domain = proofConfig.domain;
  }
  if (proofConfig.challenge) {
    proof.challenge = proofConfig.challenge;
  }

  return { ...credential, proof };
}

/**
 * Sign a credential with an EdDSA Data Integrity proof (Delegated Signing).
 *
 * Full signing path where the Ed25519 private key is available server-side.
 */
export async function signCredentialEdDsa(
  unsignedVC: UnsignedCredential,
  signingKey: SigningKey,
  options: ProofOptions,
): Promise<VerifiableCredential> {
  if (signingKey.algorithm !== "Ed25519") {
    throw new CryptoError(`EdDSA Data Integrity requires Ed25519 key, got ${signingKey.algorithm}`);
  }

  const { dataToSign, proofConfig } = await prepareEdDsaProof(unsignedVC, {
    ...options,
    verificationMethod: options.verificationMethod || signingKey.id,
  });

  try {
    const signature = sign(null, dataToSign, signingKey.privateKey);
    return completeEdDsaProof(unsignedVC, proofConfig, new Uint8Array(signature));
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `EdDSA signing failed: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Verify an EdDSA Data Integrity proof on a VerifiableCredential.
 */
export async function verifyEdDsaProof(
  credential: VerifiableCredential,
  options?: VerifyOptions,
): Promise<VerificationResult> {
  try {
    const { proof } = credential;
    if (!proof) {
      return { verified: false, error: "Credential has no proof" };
    }
    if (proof.type !== "DataIntegrityProof") {
      return { verified: false, error: `Unsupported proof type: ${proof.type}` };
    }
    if (proof.cryptosuite !== EDDSA_CRYPTOSUITE) {
      return { verified: false, error: `Unsupported cryptosuite: ${proof.cryptosuite}` };
    }
    if (!proof.proofValue) {
      return { verified: false, error: "Proof has no proofValue" };
    }

    const signatureBytes = multibaseDecode(proof.proofValue);
    if (signatureBytes.length !== ED25519_SIGNATURE_LENGTH) {
      return {
        verified: false,
        error: `Invalid Ed25519 signature length: expected ${ED25519_SIGNATURE_LENGTH} bytes, got ${signatureBytes.length}`,
      };
    }

    const publicKey = resolvePublicKey(options);
    if (!publicKey) {
      return {
        verified: false,
        error: "Unable to resolve public key from verificationMethod",
      };
    }

    // Reconstruct the proof config
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { proof: _proof, ...unsignedDoc } = credential;
    const proofConfig: ProofConfig = {
      "@context": credential["@context"] as (string | Record<string, unknown>)[],
      type: proof.type as "DataIntegrityProof",
      cryptosuite: proof.cryptosuite as string,
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

    const dataToVerify = await computeSigningInput(
      unsignedDoc as Record<string, unknown>,
      proofConfig,
      "sha256",
    );

    const verified = verify(null, dataToVerify, publicKey, signatureBytes);

    return verified
      ? { verified: true }
      : { verified: false, error: "Signature verification failed" };
  } catch (error) {
    if (
      error instanceof TypeError ||
      error instanceof ReferenceError ||
      error instanceof SyntaxError ||
      error instanceof RangeError
    ) {
      throw error;
    }
    return {
      verified: false,
      error: `Verification error: ${error instanceof Error ? error.message : "unknown error"}`,
    };
  }
}

function resolvePublicKey(options?: VerifyOptions): KeyObject | undefined {
  if (options?.publicKey) {
    return options.publicKey;
  }
  return undefined;
}
