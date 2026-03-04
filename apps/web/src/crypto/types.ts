/**
 * Types for browser extension communication and signing provider abstraction.
 *
 * These types are used on the web side only. They mirror the types from
 * @opencred/signing but without Node.js dependencies (since this runs in
 * the browser).
 */

/** Supported signing algorithms. EC keys use Data Integrity proofs, RSA keys use JWS proofs. */
export type WebSigningAlgorithm = "P-256" | "P-384" | "RSA-2048" | "RSA-3072" | "RSA-4096";

/** Metadata about a signer — safe to display in the UI. */
export interface SignerMetadata {
  id: string;
  algorithm: WebSigningAlgorithm;
  type: "software" | "pkcs11" | "os-cert";
  fingerprint: string;
  label?: string;
  certificateChain?: string[];
}

/** PKCS#11 slot information. */
export interface SlotInfo {
  index: number;
  description: string;
  tokenPresent: boolean;
  tokenLabel?: string;
  tokenManufacturer?: string;
}

/** PKCS#11 token key information. */
export interface TokenKeyInfo {
  label: string;
  id: string;
  keyType: string;
  hasPublicKey: boolean;
}

/** OS certificate information. */
export interface CertInfo {
  id: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validUntil: string;
  keyAlgorithm: string;
  isExportable: boolean;
  thumbprint: string;
}

/** Extension detection result. */
export interface ExtensionDetectResult {
  available: boolean;
  version?: string;
}

/** Unified web signer abstraction. */
export interface WebSigner {
  /** The public key identifier (did:key or JWK-derived ID). */
  publicKeyId: string;
  /** Sign data (base64url encoded) and return base64url signature. */
  sign(dataBase64url: string): Promise<string>;
  /** The key algorithm — determines proof mechanism (DI vs JWS). */
  algorithm: WebSigningAlgorithm;
  /** Certificate chain from PFX/token/OS store, if available (PEM strings). */
  certificateChain?: string[];
  /** Signer metadata for display. */
  metadata: {
    type: "jwk" | "pfx" | "pem" | "pkcs11" | "os-cert";
    label?: string;
  };
}
