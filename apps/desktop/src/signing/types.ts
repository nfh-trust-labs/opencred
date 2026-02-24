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
 *  - The id is a did:key verification method ID derived from the public key.
 */

/**
 * Metadata about a signer -- safe to transmit over IPC and display in the UI.
 * Never contains private key material.
 */
export interface SignerMetadata {
  /** The did:key verification method identifier. */
  id: string;
  /** The ECDSA curve -- only P-256 is supported for ecdsa-rdfc-2019. */
  algorithm: "P-256";
  /** The signer type. */
  type: "software" | "pkcs11" | "os-cert";
  /** SHA-256 fingerprint of the public key (hex-encoded). */
  fingerprint: string;
  /** Optional user-friendly label. */
  label?: string;
}

/**
 * Common signer interface that all key sources implement.
 *
 * software-signer, PKCS#11 signer, and OS cert signer all conform to this
 * interface so the signing flow can be key-source agnostic.
 */
export interface Signer {
  /** The did:key verification method identifier. */
  readonly id: string;
  /** The ECDSA curve. */
  readonly algorithm: "P-256";
  /** The signer type. */
  readonly type: "software" | "pkcs11" | "os-cert";
  /** Safe metadata (no private key material). */
  readonly metadata: SignerMetadata;
  /**
   * Sign data and return a raw r||s ECDSA signature (64 bytes for P-256).
   *
   * The caller provides the bytes to sign (the concatenated hash pair from
   * proof preparation). The signer uses createSign("SHA256") which applies
   * SHA-256 before ECDSA -- this matches the existing signCredential() flow
   * in @opencred/crypto.
   */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * Detected key format when importing from a file.
 */
export type KeyFormat = "pem" | "jwk" | "pkcs8-der";
