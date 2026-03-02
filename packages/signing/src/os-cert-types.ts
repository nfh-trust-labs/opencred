/**
 * Type definitions for OS certificate store signing.
 *
 * Defines the platform-agnostic interface for interacting with OS-managed
 * certificate stores (macOS Keychain, Windows CNG, Linux fallback).
 *
 * SECURITY INVARIANTS:
 *  - Private keys NEVER leave the OS certificate store.
 *  - Only certificate metadata and public keys cross the boundary.
 *  - No key material is ever logged.
 *  - Signing operations are delegated to the OS — the private key is
 *    accessed only by the OS cryptography subsystem.
 */

/**
 * Metadata about a certificate in the OS certificate store.
 *
 * All fields are safe to transmit over IPC and display in the UI.
 * No private key material is included.
 */
export interface OsCertInfo {
  /** Platform-specific certificate identifier (Keychain persistent ref, Windows thumbprint, etc.). */
  id: string;
  /** Certificate subject Common Name (CN). */
  subject: string;
  /** Certificate issuer Common Name (CN). */
  issuer: string;
  /** Certificate serial number (hex-encoded). */
  serialNumber: string;
  /** Certificate validity start (ISO 8601). */
  validFrom: string;
  /** Certificate validity end (ISO 8601). */
  validUntil: string;
  /** Key algorithm description (e.g., "ECDSA P-256"). */
  keyAlgorithm: string;
  /** Whether the private key is marked as exportable. */
  isExportable: boolean;
  /** SHA-256 thumbprint of the DER-encoded certificate (hex-encoded). */
  thumbprint: string;
}

/**
 * Platform-specific provider interface for OS certificate store operations.
 *
 * Each platform (macOS, Windows) implements this interface. The provider
 * handles all interaction with the native OS APIs. The private key never
 * leaves the OS — signing is performed by the OS cryptography subsystem.
 */
export interface OsCertProvider {
  /**
   * Enumerate signing certificates from the OS certificate store.
   *
   * Filters for certificates with EC P-256 private keys that are suitable
   * for digital signing. Returns metadata only — no key material.
   *
   * @returns Array of certificate metadata.
   */
  listCertificates(): Promise<OsCertInfo[]>;

  /**
   * Sign data using a certificate's private key via the OS cryptography API.
   *
   * The OS handles the actual signing — the private key never leaves the OS.
   * The data is hashed with SHA-256 before ECDSA signing (matching the
   * software signer flow). Returns raw r||s (64 bytes for P-256).
   *
   * @param certificateId - Platform-specific certificate identifier.
   * @param data - The data to sign (will be SHA-256 hashed then signed).
   * @returns Raw r||s ECDSA signature (64 bytes for P-256).
   */
  sign(certificateId: string, data: Uint8Array): Promise<Uint8Array>;

  /**
   * Extract the SEC1 compressed public key from a certificate.
   *
   * Returns the 33-byte compressed public key (0x02/0x03 prefix + 32-byte x).
   * This is used for did:key derivation and fingerprint computation.
   *
   * @param certificateId - Platform-specific certificate identifier.
   * @returns SEC1 compressed public key bytes (33 bytes for P-256).
   */
  getPublicKey(certificateId: string): Promise<Uint8Array>;
}

/**
 * Options for creating an OS certificate store signer.
 */
export interface OsCertSignerOptions {
  /** The runtime platform. */
  platform: "darwin" | "win32" | "linux";
  /** Platform-specific certificate identifier. */
  certificateId: string;
  /** Optional user-friendly label. */
  label?: string;
}

/**
 * Result of listing certificates from the OS cert store via IPC.
 */
export interface OsCertListResult {
  certificates: OsCertInfo[];
  platform: "darwin" | "win32" | "linux";
  /** Human-readable store name (e.g., "macOS Keychain", "Windows Certificate Store"). */
  storeName: string;
}
