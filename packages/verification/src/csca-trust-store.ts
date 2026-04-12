/**
 * CSCA Trust Store — manages a set of trusted Country Signing Certificate
 * Authority (CSCA) root certificates for X.509 chain validation.
 *
 * The trust store loads PEM and DER certificate files from a directory and
 * provides a fast lookup by SHA-256 fingerprint. This is used by
 * `checkX509Chain` to validate that the root of a credential's x5c chain
 * is trusted.
 *
 * Design decisions:
 *  - Fingerprint comparison (SHA-256 over the full DER encoding) is used
 *    for trust lookups. This is the simplest, most reliable method — it
 *    avoids subject/issuer matching ambiguities and ASN.1 encoding
 *    subtleties.
 *  - PEM files may contain multiple concatenated certificates (common in
 *    CA bundle distributions). Each certificate is loaded individually.
 *  - DER files (.der extension) are loaded as raw binary certificates.
 *  - If the directory does not exist or is empty, the store is created
 *    empty. The caller decides whether an empty store is acceptable
 *    (graceful degradation) or an error (fail-closed).
 *
 * SECURITY: This module only handles public certificates — never private
 * keys. Certificate bytes are never logged; only fingerprints and counts
 * are surfaced via the `onWarning` callback.
 */

import { readdir, readFile } from "node:fs/promises";
import { createHash, X509Certificate } from "node:crypto";
import path from "node:path";

/**
 * Callback for surfacing non-fatal issues during trust store loading.
 * Callers should wire this to their logger (e.g. `pino.warn`).
 */
export type TrustStoreWarningCallback = (message: string) => void;

/**
 * Options for constructing a CscaTrustStore from a directory.
 */
export interface CscaTrustStoreOptions {
  /**
   * Called when a non-fatal issue is encountered during loading — missing
   * directory, unreadable file, file with no valid certificates, etc.
   * Callers should wire this to their application logger so operators can
   * detect misconfigured trust stores.
   */
  onWarning?: TrustStoreWarningCallback;
}

/**
 * A trust store of CSCA root certificates, keyed by SHA-256 fingerprint.
 *
 * Used by the X.509 chain check to validate that a credential's certificate
 * chain terminates at a trusted root.
 */
export class CscaTrustStore {
  private readonly trustedCerts: Map<string, X509Certificate>;

  /**
   * Construct a CscaTrustStore from an already-loaded map of certificates.
   * Prefer `CscaTrustStore.fromDirectory()` or `CscaTrustStore.empty()`.
   */
  constructor(certs?: Map<string, X509Certificate>) {
    this.trustedCerts = certs ?? new Map();
  }

  /**
   * Load all certificate files from a directory and return a populated
   * trust store. Handles `.pem`, `.crt`, `.cer` (PEM-encoded) and `.der`
   * (DER-encoded) files. PEM files with multiple concatenated certificates
   * are split and each certificate is loaded individually.
   *
   * If the directory does not exist or is empty, returns an empty store
   * and calls `onWarning` — this supports graceful degradation.
   */
  static async fromDirectory(
    certDir: string,
    options?: CscaTrustStoreOptions,
  ): Promise<CscaTrustStore> {
    const onWarning = options?.onWarning;
    const certs = new Map<string, X509Certificate>();

    let entries: string[];
    try {
      entries = await readdir(certDir);
    } catch {
      onWarning?.(`CSCA trust store directory not found or unreadable: ${certDir}`);
      return new CscaTrustStore(certs);
    }

    for (const entry of entries) {
      const lower = entry.toLowerCase();
      const fullPath = path.join(certDir, entry);

      if (lower.endsWith(".der")) {
        // DER-encoded binary certificate
        try {
          const derBuf = await readFile(fullPath);
          const cert = new X509Certificate(derBuf);
          const fingerprint = computeFingerprint(cert);
          certs.set(fingerprint, cert);
        } catch {
          onWarning?.(`Failed to load DER certificate: ${fullPath}`);
        }
        continue;
      }

      if (
        !lower.endsWith(".pem") &&
        !lower.endsWith(".crt") &&
        !lower.endsWith(".cer")
      ) {
        // Skip non-certificate files silently (e.g. README.md)
        continue;
      }

      // PEM-encoded certificate file (may contain multiple certs)
      let content: string;
      try {
        content = await readFile(fullPath, "utf8");
      } catch {
        onWarning?.(`Failed to read certificate file: ${fullPath}`);
        continue;
      }

      const pemBlocks = splitPemBlocks(content);
      if (pemBlocks.length === 0) {
        onWarning?.(`No PEM certificate blocks found in: ${fullPath}`);
        continue;
      }

      for (const pem of pemBlocks) {
        try {
          const cert = new X509Certificate(pem);
          const fingerprint = computeFingerprint(cert);
          certs.set(fingerprint, cert);
        } catch {
          onWarning?.(`Failed to parse a certificate block in: ${fullPath}`);
        }
      }
    }

    if (certs.size === 0) {
      onWarning?.(`CSCA trust store is empty — no valid certificates found in: ${certDir}`);
    }

    return new CscaTrustStore(certs);
  }

  /**
   * Create an empty trust store. Used for graceful degradation when no
   * trust store directory is configured.
   */
  static empty(): CscaTrustStore {
    return new CscaTrustStore();
  }

  /**
   * Check whether a certificate is in the trust store by comparing its
   * SHA-256 fingerprint against the stored fingerprints.
   */
  isTrusted(cert: X509Certificate): boolean {
    const fingerprint = computeFingerprint(cert);
    return this.trustedCerts.has(fingerprint);
  }

  /**
   * The number of certificates in the trust store.
   */
  get size(): number {
    return this.trustedCerts.size;
  }

  /**
   * Return the PEM-encoded trust anchor certificates as an array of strings.
   * This bridges the CscaTrustStore class to the existing `trustAnchors: string[]`
   * interface used by `checkX509Chain`.
   */
  toPemArray(): string[] {
    return Array.from(this.trustedCerts.values()).map((cert) => cert.toString());
  }
}

/**
 * Compute the SHA-256 fingerprint of a certificate's DER encoding.
 * This is the canonical identifier for trust store lookups — two
 * certificates with the same fingerprint are byte-identical.
 */
function computeFingerprint(cert: X509Certificate): string {
  // X509Certificate.raw gives us the DER-encoded certificate bytes.
  return createHash("sha256").update(cert.raw).digest("hex");
}

/**
 * Split a PEM string that may contain multiple concatenated certificates
 * into individual single-certificate PEM blocks. Lines outside CERTIFICATE
 * blocks are ignored. Each returned block ends with a trailing newline.
 */
function splitPemBlocks(input: string): string[] {
  const blocks: string[] = [];
  const lines = input.split(/\r?\n/);
  let inBlock = false;
  let buffer: string[] = [];
  for (const line of lines) {
    if (line.includes("-----BEGIN CERTIFICATE-----")) {
      inBlock = true;
      buffer = [line];
      continue;
    }
    if (inBlock) {
      buffer.push(line);
      if (line.includes("-----END CERTIFICATE-----")) {
        blocks.push(buffer.join("\n") + "\n");
        inBlock = false;
        buffer = [];
      }
    }
  }
  return blocks;
}
