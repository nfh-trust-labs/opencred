import type { KeyObject } from "node:crypto";

/**
 * Supported signing algorithms.
 *
 * EC keys use Data Integrity proofs (ecdsa-rdfc-2019).
 * RSA keys use VC-JOSE-COSE enveloping proofs (JWS with PS256).
 */
export type SigningAlgorithm = "P-256" | "P-384" | "RSA-2048" | "RSA-3072" | "RSA-4096" | "Ed25519";

/**
 * Options for creating a Data Integrity proof.
 */
export interface ProofOptions {
  /** The verification method identifier (e.g., DID URL). */
  verificationMethod: string;
  /** The purpose of the proof (e.g., "assertionMethod"). */
  proofPurpose: string;
  /** ISO 8601 timestamp for the proof creation. Auto-generated if omitted. */
  created?: string;
  /** The domain the proof is bound to (optional). */
  domain?: string;
  /** A challenge nonce (optional). */
  challenge?: string;
}

/**
 * A prepared proof for two-phase (Interface) signing.
 * Contains the data that must be signed externally.
 */
export interface PreparedProof {
  /** The bytes that must be signed by the external signer (SHA-256(proofConfig) || SHA-256(document)). */
  dataToSign: Uint8Array;
  /** The proof configuration object (will be embedded once signed). */
  proofConfig: ProofConfig;
}

/**
 * Internal proof configuration before signing.
 */
export interface ProofConfig {
  "@context": (string | Record<string, unknown>)[];
  type: "DataIntegrityProof";
  cryptosuite: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  domain?: string;
  challenge?: string;
}

/**
 * Options for creating a VC-JOSE-COSE JWS enveloping proof.
 */
export interface JwsProofOptions {
  /** The verification method identifier (e.g., "did:jwk:...#0"). */
  verificationMethod: string;
  /** ISO 8601 timestamp for the proof creation. Auto-generated if omitted. */
  created?: string;
}

/**
 * A prepared JWS proof for two-phase (Interface) signing.
 */
export interface JwsPreparedProof {
  /** The base64url(header) + "." + base64url(payload) string that must be signed. */
  signingInput: string;
  /** The JWS protected header (for reference). */
  protectedHeader: Record<string, unknown>;
}

/**
 * A signing key for delegated signing (OpenCred-managed keys).
 * Uses Node.js KeyObject to prevent accidental key material exposure.
 */
export interface SigningKey {
  /** The verification method identifier (e.g., "did:key:z...#z..." or "did:jwk:...#0"). */
  id: string;
  /** The private key as a Node.js KeyObject (never logged or serialized). */
  privateKey: KeyObject;
  /** The public key as a Node.js KeyObject. */
  publicKey: KeyObject;
  /** The signing algorithm. EC keys use Data Integrity proofs, RSA keys use JWS proofs. */
  algorithm: SigningAlgorithm;
}

/**
 * Result of a proof verification operation.
 */
export interface VerificationResult {
  /** Whether the proof verified successfully. */
  verified: boolean;
  /** Error message if verification failed. */
  error?: string;
}

/**
 * Options for verifying a Data Integrity proof.
 */
export interface VerifyOptions {
  /** A pre-resolved public key to use for verification (skips key resolution). */
  publicKey?: KeyObject;
}
