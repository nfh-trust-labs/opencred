/**
 * Proof format router — central routing for two-phase signing across all proof formats.
 *
 * Routes the UI's 3-value proof format choice ("vc-jwt" | "data-integrity" | "sd-jwt-vc")
 * to the correct crypto functions. "data-integrity" auto-selects ecdsa-rdfc-2019 or
 * eddsa-rdfc-2022 based on the signer's algorithm.
 *
 * SECURITY INVARIANTS:
 *  - The private key never leaves the issuer's machine.
 *  - Key material is NEVER logged.
 *  - No network requests are made during signing.
 */

import { CryptoError } from "@opencred/shared";
import {
  prepareVcJwtProof,
  completeVcJwtProof,
  prepareProof,
  completeProof,
  prepareEdDsaProof,
  completeEdDsaProof,
  prepareSdJwtVcProof,
  completeSdJwtVcProof,
} from "@opencred/crypto";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import type { UiProofFormat } from "../shared/ipc-types.js";
import type { Signer } from "./types.js";

export interface SignWithFormatOptions {
  verificationMethod: string;
  selectiveDisclosureClaims?: string[];
  /** Verifiable Credential Type for SD-JWT-VC (derived from credential types). */
  vct?: string;
}

export interface SignWithFormatResult {
  /** The signed output — JSON string for vc-jwt/data-integrity, compact string for SD-JWT-VC. */
  signedOutput: string;
  /** True when output is a compact token (SD-JWT-VC), false for JSON. */
  isCompactToken: boolean;
}

/**
 * Returns true if the algorithm is an RSA variant.
 */
function isRsa(algorithm: string): boolean {
  return algorithm.startsWith("RSA");
}

/**
 * Returns true if the algorithm is Ed25519.
 */
function isEdDsa(algorithm: string): boolean {
  return algorithm === "Ed25519";
}

/**
 * Sign a credential using the specified proof format.
 *
 * Routes to the correct crypto functions based on proof format and key algorithm.
 * Throws CryptoError with a user-facing message for incompatible combinations.
 */
export async function signWithFormat(
  signer: Signer,
  unsignedCredential: UnsignedCredential,
  proofFormat: UiProofFormat,
  options: SignWithFormatOptions,
): Promise<SignWithFormatResult> {
  switch (proofFormat) {
    case "vc-jwt":
      return signVcJwt(signer, unsignedCredential, options);
    case "data-integrity":
      return signDataIntegrity(signer, unsignedCredential, options);
    case "sd-jwt-vc":
      return signSdJwtVc(signer, unsignedCredential, options);
    default:
      throw new CryptoError(`Unknown proof format: ${proofFormat as string}`);
  }
}

/**
 * VC-JWT two-phase signing — works with all key algorithms.
 */
async function signVcJwt(
  signer: Signer,
  unsignedCredential: UnsignedCredential,
  options: SignWithFormatOptions,
): Promise<SignWithFormatResult> {
  const vcAsRecord = unsignedCredential as unknown as Record<string, unknown>;
  const { signingInput } = prepareVcJwtProof(vcAsRecord, signer.algorithm, {
    verificationMethod: options.verificationMethod,
  });

  const dataToSign = new TextEncoder().encode(signingInput);
  const signatureBytes = await signer.sign(dataToSign);
  const jwt = completeVcJwtProof(signingInput, signatureBytes);

  const signedCredential: VerifiableCredential = {
    ...unsignedCredential,
    proof: {
      type: "JsonWebSignature2020",
      jwt,
    },
  } as unknown as VerifiableCredential;

  return {
    signedOutput: JSON.stringify(signedCredential),
    isCompactToken: false,
  };
}

/**
 * Data Integrity two-phase signing — ECDSA (P-256/P-384) or EdDSA (Ed25519).
 * RSA keys are not supported — caller must validate before calling.
 */
async function signDataIntegrity(
  signer: Signer,
  unsignedCredential: UnsignedCredential,
  options: SignWithFormatOptions,
): Promise<SignWithFormatResult> {
  if (isRsa(signer.algorithm)) {
    throw new CryptoError(
      "Data Integrity proofs are not supported with RSA keys. Please select VC-JWT or SD-JWT-VC.",
    );
  }

  const proofOptions = {
    verificationMethod: options.verificationMethod,
    proofPurpose: "assertionMethod",
  };

  let signedCredential: VerifiableCredential;

  if (isEdDsa(signer.algorithm)) {
    const { dataToSign, proofConfig } = await prepareEdDsaProof(unsignedCredential, proofOptions);
    const signatureBytes = await signer.sign(dataToSign);
    signedCredential = completeEdDsaProof(unsignedCredential, proofConfig, signatureBytes);
  } else {
    // ECDSA (P-256, P-384)
    const { dataToSign, proofConfig } = await prepareProof(
      unsignedCredential,
      proofOptions,
      signer.algorithm as "P-256" | "P-384",
    );
    const signatureBytes = await signer.sign(dataToSign);
    signedCredential = completeProof(unsignedCredential, proofConfig, signatureBytes);
  }

  return {
    signedOutput: JSON.stringify(signedCredential),
    isCompactToken: false,
  };
}

/**
 * SD-JWT-VC two-phase signing — works with all key algorithms.
 */
async function signSdJwtVc(
  signer: Signer,
  unsignedCredential: UnsignedCredential,
  options: SignWithFormatOptions,
): Promise<SignWithFormatResult> {
  const vct = options.vct ?? "VerifiableCredential";

  const sdJwtOptions = {
    selectiveDisclosureClaims: options.selectiveDisclosureClaims ?? [],
    vct,
    verificationMethod: options.verificationMethod,
  };

  const { signingInput, disclosures } = prepareSdJwtVcProof(
    unsignedCredential,
    signer.algorithm,
    sdJwtOptions,
  );

  const dataToSign = new TextEncoder().encode(signingInput);
  const signatureBytes = await signer.sign(dataToSign);
  const compactString = completeSdJwtVcProof(signingInput, signatureBytes, disclosures);

  return {
    signedOutput: compactString,
    isCompactToken: true,
  };
}
