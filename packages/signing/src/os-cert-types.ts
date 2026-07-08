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

import type { SigningAlgorithm } from "@opencred/crypto";

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
  /** Key algorithm (e.g., "P-256", "RSA-2048"). */
  keyAlgorithm: SigningAlgorithm;
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
   * Returns certificates with EC or RSA private keys suitable for digital
   * signing. Returns metadata only — no key material.
   *
   * @returns Array of certificate metadata.
   */
  listCertificates(): Promise<OsCertInfo[]>;

  /**
   * Sign data using a certificate's private key via the OS cryptography API.
   *
   * The OS handles the actual signing — the private key never leaves the OS.
   * For EC keys: returns raw r||s (64 bytes for P-256, 96 bytes for P-384).
   * For RSA keys: returns RSASSA-PSS signature (length depends on modulus).
   *
   * @param certificateId - Platform-specific certificate identifier.
   * @param data - The data to sign (will be hashed then signed).
   * @returns Raw signature bytes.
   */
  sign(certificateId: string, data: Uint8Array): Promise<Uint8Array>;

  /**
   * Extract the public key from a certificate.
   *
   * For EC keys: returns SEC1 compressed public key (33 bytes for P-256, 49 for P-384).
   * For RSA keys: returns SPKI DER-encoded public key.
   *
   * @param certificateId - Platform-specific certificate identifier.
   * @returns Public key bytes.
   */
  getPublicKey(certificateId: string): Promise<Uint8Array>;

  /**
   * Get the certificate chain (PEM-encoded) for a certificate.
   * Optional — not all providers support this.
   *
   * @param certificateId - Platform-specific certificate identifier.
   * @returns PEM-encoded certificate chain (DSC, intermediates), or empty array.
   */
  getCertificateChain?(certificateId: string): Promise<string[]>;
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
  /** Key algorithm. When omitted, defaults to "P-256" for backward compatibility. */
  keyAlgorithm?: SigningAlgorithm;
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
