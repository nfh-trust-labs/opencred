/**
 * Types for browser extension communication and signing provider abstraction.
 *
 * These types are used on the web side only. They mirror the types from
 * @opencred/signing but without Node.js dependencies (since this runs in
 * the browser).
 */

/** Metadata about a signer — safe to display in the UI. */
export interface SignerMetadata {
  id: string;
  algorithm: "P-256";
  type: "software" | "pkcs11" | "os-cert";
  fingerprint: string;
  label?: string;
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
  /** Signer metadata for display. */
  metadata: {
    type: "jwk" | "pkcs11" | "os-cert";
    label?: string;
  };
}
