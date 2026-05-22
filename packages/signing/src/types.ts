/**
 * Common signer interface for the OpenCred desktop app.
 *
 * All signer implementations (software, PKCS#11, OS cert store) MUST
 * implement this interface. The private key material is NEVER exposed
 * through these types -- only metadata and a sign() method that operates
 * on opaque data.
 *
 * SECURITY INVARIANTS:
 *  - The sign() method must never leak key material in errors or logs.
 *  - Metadata contains the key fingerprint (SHA-256 of public key), never
 *    the key itself.
 *  - The id is a did:key or did:jwk verification method ID derived from the public key.
 */

import type { SigningAlgorithm } from "@opencred/crypto";

/**
 * Metadata about a signer -- safe to transmit over IPC and display in the UI.
 * Never contains private key material.
 */
export interface SignerMetadata {
  /** The did:key or did:jwk verification method identifier. */
  id: string;
  /** The signing algorithm (EC curve or RSA modulus size). */
  algorithm: SigningAlgorithm;
  /** The signer type. */
  type: "software" | "pkcs11" | "os-cert";
  /** SHA-256 fingerprint of the public key (hex-encoded). */
  fingerprint: string;
  /** Optional user-friendly label. */
  label?: string;
  /** PEM-encoded certificate chain (DSC, intermediates). Present when imported from PFX/token/OS store. */
  certificateChain?: string[];
  /**
   * Public key in JWK form. Optional: software signers expose this for
   * callers that need to assemble DID Documents (e.g. did:web auto-publish
   * at startup — see `apps/server/src/index.ts` `OPENCRED_AUTO_PUBLISH_KEY`).
   * PKCS#11 and OS-cert signers do not currently expose it; callers must
   * tolerate the missing field gracefully.
   *
   * The shape matches the W3C JWK structure: `{ kty, crv, x, y }` for EC
   * keys, `{ kty, n, e }` for RSA. NEVER contains private parameters
   * (`d`, `p`, `q`, etc.) — those would violate CLAUDE.md security
   * invariant #2 ("never log key material") because metadata IS surfaced
   * in `GET /v1/keys` responses.
   */
  publicKeyJwk?: Record<string, unknown>;
}

/**
 * Common signer interface that all key sources implement.
 *
 * software-signer, PKCS#11 signer, and OS cert signer all conform to this
 * interface so the signing flow can be key-source agnostic.
 */
export interface Signer {
  /** The did:key or did:jwk verification method identifier. */
  readonly id: string;
  /** The signing algorithm. */
  readonly algorithm: SigningAlgorithm;
  /** The signer type. */
  readonly type: "software" | "pkcs11" | "os-cert";
  /** Safe metadata (no private key material). */
  readonly metadata: SignerMetadata;
  /**
   * Sign data and return a raw signature.
   *
   * For EC keys: raw r||s (64 bytes for P-256, 96 bytes for P-384).
   * For RSA keys: RSASSA-PSS signature (256/384/512 bytes depending on modulus).
   */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * Detected key format when importing from a file.
 */
export type KeyFormat = "pem" | "jwk" | "pkcs8-der" | "pfx";
