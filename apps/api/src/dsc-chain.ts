import { X509Certificate } from "node:crypto";
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, extname } from "node:path";
import type { Logger } from "./logger.js";

export interface DscChainCheck {
  passed: boolean;
  detail?: string;
}

/**
 * An in-memory store of trusted CSCA (Country Signing CA) certificates.
 * Loaded once at startup from a directory of PEM files.
 */
export class TrustStore {
  private readonly cscaCerts: X509Certificate[] = [];

  get size(): number {
    return this.cscaCerts.length;
  }

  /**
   * Load CSCA certificates from a directory of PEM files.
   * Only files with .pem or .crt extensions are loaded.
   * Invalid certificates are logged and skipped.
   */
  static load(directoryPath: string, logger?: Logger): TrustStore {
    const store = new TrustStore();

    if (!existsSync(directoryPath)) {
      logger?.warn({ path: directoryPath }, "CSCA trust store directory does not exist");
      return store;
    }

    const stat = statSync(directoryPath);
    if (!stat.isDirectory()) {
      logger?.warn({ path: directoryPath }, "CSCA trust store path is not a directory");
      return store;
    }

    const files = readdirSync(directoryPath);
    for (const file of files) {
      const ext = extname(file).toLowerCase();
      if (ext !== ".pem" && ext !== ".crt") {
        continue;
      }

      const filePath = join(directoryPath, file);
      try {
        const pem = readFileSync(filePath, "utf-8");
        const cert = new X509Certificate(pem);
        store.cscaCerts.push(cert);
      } catch (err) {
        logger?.warn(
          { file, error: err instanceof Error ? err.message : String(err) },
          "Failed to load CSCA certificate, skipping",
        );
      }
    }

    logger?.info({ count: store.cscaCerts.length, path: directoryPath }, "Loaded CSCA trust store");
    return store;
  }

  /**
   * Create a TrustStore directly from an array of X509Certificate objects.
   * Useful for testing.
   */
  static fromCertificates(certs: X509Certificate[]): TrustStore {
    const store = new TrustStore();
    store.cscaCerts.push(...certs);
    return store;
  }

  /**
   * Find a trusted CSCA that issued the given certificate.
   */
  findIssuer(cert: X509Certificate): X509Certificate | undefined {
    for (const csca of this.cscaCerts) {
      if (cert.checkIssued(csca)) {
        return csca;
      }
    }
    return undefined;
  }
}

/**
 * Validate a DSC certificate chain against the trust store.
 *
 * Validates:
 * 1. All certificates in the chain are currently valid (not expired, not before valid date)
 * 2. Each certificate is issued by the next certificate in the chain (issuer linkage)
 * 3. The root of the chain (last cert, or the single DSC) is issued by a trusted CSCA
 *
 * @param chain - Array of PEM-encoded certificates, leaf (DSC) first, intermediates next
 * @param trustStore - The loaded CSCA trust store
 */
export function validateDscChain(
  chain: string[],
  trustStore: TrustStore,
  now: Date = new Date(),
): DscChainCheck {
  if (chain.length === 0) {
    return { passed: false, detail: "Empty certificate chain" };
  }

  if (trustStore.size === 0) {
    return { passed: false, detail: "No trusted CSCA certificates loaded" };
  }

  // Parse all certificates
  const certs: X509Certificate[] = [];
  for (let i = 0; i < chain.length; i++) {
    try {
      certs.push(new X509Certificate(chain[i]));
    } catch {
      return {
        passed: false,
        detail: `Invalid certificate at position ${i} in chain`,
      };
    }
  }

  // Validate each certificate's date range
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    const notBefore = new Date(cert.validFrom);
    const notAfter = new Date(cert.validTo);

    if (now < notBefore) {
      return {
        passed: false,
        detail: `Certificate at position ${i} is not yet valid (validFrom: ${cert.validFrom})`,
      };
    }
    if (now > notAfter) {
      return {
        passed: false,
        detail: `Certificate at position ${i} has expired (validTo: ${cert.validTo})`,
      };
    }
  }

  // Validate issuer linkage within the chain
  for (let i = 0; i < certs.length - 1; i++) {
    if (!certs[i].checkIssued(certs[i + 1])) {
      return {
        passed: false,
        detail: `Certificate at position ${i} was not issued by certificate at position ${i + 1}`,
      };
    }
  }

  // The root of the provided chain must be issued by a trusted CSCA
  const chainRoot = certs[certs.length - 1];
  const trustedIssuer = trustStore.findIssuer(chainRoot);
  if (!trustedIssuer) {
    return {
      passed: false,
      detail: "Certificate chain root is not issued by any trusted CSCA",
    };
  }

  // Verify the CSCA itself is valid
  const cscaNotBefore = new Date(trustedIssuer.validFrom);
  const cscaNotAfter = new Date(trustedIssuer.validTo);
  if (now < cscaNotBefore || now > cscaNotAfter) {
    return {
      passed: false,
      detail: "Trusted CSCA certificate has expired or is not yet valid",
    };
  }

  return { passed: true };
}
