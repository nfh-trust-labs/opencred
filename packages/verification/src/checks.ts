import { resolve4, resolve6 } from "node:dns/promises";
import { isIP } from "node:net";
import { promisify } from "node:util";
import { gunzip as gunzipCb } from "node:zlib";
import type { DeDiClient } from "@opencred/dedi-client";
import { computeRevocationHash } from "@opencred/crypto";
import type { DIDResolver } from "@opencred/did";
import { isPrivateIP } from "@opencred/shared";
import { verifyDataIntegrity } from "./data-integrity.js";
import type { VerifiableCredential } from "@opencred/vc-core";
import type { VerificationCheck } from "./types.js";

const gunzip = promisify(gunzipCb);

/** Maximum compressed encodedList size in bytes (1 MB). */
const MAX_COMPRESSED_SIZE = 1_048_576;

/**
 * Check validFrom / validUntil date constraints.
 * Returns a check result indicating whether the credential is within its validity period.
 */
export function checkDates(
  validFrom?: string,
  validUntil?: string,
  now: Date = new Date(),
): VerificationCheck {
  if (validFrom) {
    const from = new Date(validFrom);
    if (isNaN(from.getTime())) {
      return { name: "date", passed: false, detail: "Invalid validFrom date" };
    }
    if (now < from) {
      return {
        name: "date",
        passed: false,
        detail: `Credential not yet valid (validFrom: ${validFrom})`,
      };
    }
  }

  if (validUntil) {
    const until = new Date(validUntil);
    if (isNaN(until.getTime())) {
      return { name: "date", passed: false, detail: "Invalid validUntil date" };
    }
    if (now > until) {
      return {
        name: "date",
        passed: false,
        detail: `Credential expired (validUntil: ${validUntil})`,
      };
    }
  }

  return { name: "date", passed: true };
}

/**
 * Check revocation status via DeDi registry.
 * Computes the JCS-canonical SHA-256 hash of the credential and queries DeDi.
 */
export async function checkRevocation(
  credential: unknown,
  dediClient: DeDiClient,
): Promise<VerificationCheck> {
  try {
    const hash = computeRevocationHash(credential);
    const record = await dediClient.queryRevocationHash(hash);
    if (record.revoked) {
      return {
        name: "revocation",
        passed: false,
        detail: `Credential revoked${record.revokedAt ? ` at ${record.revokedAt}` : ""}`,
      };
    }
    return { name: "revocation", passed: true };
  } catch {
    return {
      name: "revocation",
      passed: false,
      detail: "Unable to check revocation status: DeDi service unavailable",
    };
  }
}

// --- SSRF prevention for status list URL validation ---
//
// `isPrivateIP` is imported from @opencred/shared (the canonical SSRF helper).
// The canonical helper validates its input via `node:net`'s `isIP()`, so it
// expects bare IP literals (no surrounding brackets). Callers below strip
// brackets from IPv6 hostnames before delegating to it.

/** Known private/loopback hostnames. */
const PRIVATE_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "[::1]",
]);

/**
 * Validate a status list URL against SSRF rules.
 * - Must be a valid URL.
 * - Must use the https: scheme.
 * - Hostname must not be a private IP or loopback name.
 * - Hostname must be on the allowlist (if one is provided).
 */
function validateStatusListUrl(
  raw: string,
  allowedDomains?: string[],
): { valid: true; url: string; hostname: string } | { valid: false; detail: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { valid: false, detail: "Invalid status list URL" };
  }

  if (parsed.protocol !== "https:") {
    return { valid: false, detail: "Status list URL must use HTTPS" };
  }

  const hostname = parsed.hostname.toLowerCase();

  if (PRIVATE_HOSTNAMES.has(hostname)) {
    return { valid: false, detail: "Status list URL points to a private/loopback host" };
  }

  // Check if hostname is a raw IP literal (IPv4 or bracketed IPv6).
  // URL.hostname returns bracketed IPv6 (e.g. "[::1]"); canonical isPrivateIP
  // expects the bare literal, so we strip brackets before delegation.
  const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const isIPv6 = hostname.startsWith("[") || hostname.includes(":");
  if (isIPv4 || isIPv6) {
    const bare = hostname.replace(/^\[|\]$/g, "");
    if (isPrivateIP(bare)) {
      return { valid: false, detail: "Status list URL points to a private/reserved IP" };
    }
  }

  if (allowedDomains && allowedDomains.length > 0) {
    const allowed = allowedDomains.some(
      (d) => hostname === d.toLowerCase() || hostname.endsWith(`.${d.toLowerCase()}`),
    );
    if (!allowed) {
      return { valid: false, detail: "Status list URL domain is not on the allowlist" };
    }
  }

  return { valid: true, url: parsed.toString(), hostname };
}

/**
 * Resolve a hostname to an IP and validate that none of the resolved IPs are private.
 * Prevents DNS rebinding attacks by pinning the resolved IP for use in the fetch.
 */
export async function resolveAndValidateIp(
  hostname: string,
): Promise<{ address: string; family: 4 | 6 }> {
  let addresses: string[] = [];
  let family: 4 | 6 = 4;

  try {
    addresses = await resolve4(hostname);
  } catch {
    // resolve4 failed, try IPv6
  }

  if (addresses.length === 0) {
    try {
      addresses = await resolve6(hostname);
      family = 6;
    } catch {
      throw new Error(`DNS resolution failed for ${hostname}`);
    }
  }

  if (addresses.length === 0) {
    throw new Error(`DNS resolution failed for ${hostname}`);
  }

  // Validate ALL resolved IPs — if any are private, reject
  for (const addr of addresses) {
    if (isPrivateIP(addr)) {
      throw new Error(`DNS resolved to private/reserved IP for ${hostname}`);
    }
  }

  return { address: addresses[0], family };
}

/** Options for the BitstringStatusList check. */
export interface BitstringStatusListOptions {
  /** Optional allowlist of permitted domains for status list URLs. */
  allowedDomains?: string[];
  /** Optional DID resolver for verifying the proof on the status list credential. */
  didResolver?: DIDResolver;
}

/**
 * Check BitstringStatusList when credentialStatus.type is BitstringStatusListEntry.
 * Fetches the status list and checks the bit at the given index.
 *
 * Security measures:
 * - SSRF: Validates URL scheme (HTTPS only), blocks private IPs and loopback, supports domain allowlist.
 * - DNS rebinding: Resolves hostname and pins IP before fetch; validates resolved IPs against private ranges.
 * - Decompression bomb: Rejects compressed data larger than MAX_COMPRESSED_SIZE (1 MB).
 * - Event loop blocking: Uses async gunzip instead of gunzipSync.
 * - Proof verification: Optionally verifies the proof on the fetched status list credential.
 */
export async function checkBitstringStatusList(
  credentialStatus: Record<string, unknown>,
  options: BitstringStatusListOptions = {},
): Promise<VerificationCheck> {
  try {
    const statusListIndex = credentialStatus["statusListIndex"];
    const statusListCredential = credentialStatus["statusListCredential"];

    if (statusListIndex === undefined || statusListCredential === undefined) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Missing statusListIndex or statusListCredential in credentialStatus",
      };
    }

    const index = Number(statusListIndex);
    if (!Number.isInteger(index) || index < 0) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Invalid statusListIndex: ${String(statusListIndex)}`,
      };
    }

    // #123: Validate URL to prevent SSRF
    const urlValidation = validateStatusListUrl(
      String(statusListCredential),
      options.allowedDomains,
    );
    if (!urlValidation.valid) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: urlValidation.detail,
      };
    }

    // DNS rebinding prevention: resolve hostname and pin IP before fetch
    let fetchUrl = urlValidation.url;
    const fetchHeaders: Record<string, string> = {};

    const parsedUrl = new URL(urlValidation.url);
    const hostname = parsedUrl.hostname;

    if (!isIP(hostname)) {
      const resolved = await resolveAndValidateIp(hostname);
      // Replace hostname with resolved IP; set Host header to original hostname
      const pinnedUrl = new URL(urlValidation.url);
      if (resolved.family === 6) {
        pinnedUrl.hostname = `[${resolved.address}]`;
      } else {
        pinnedUrl.hostname = resolved.address;
      }
      fetchUrl = pinnedUrl.toString();
      fetchHeaders["Host"] = hostname;
    }

    const response = await globalThis.fetch(fetchUrl, {
      redirect: "error", // Prevent redirect-based SSRF
      headers: fetchHeaders,
    });
    if (!response.ok) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Failed to fetch status list: HTTP ${response.status}`,
      };
    }

    const statusListVC = (await response.json()) as Record<string, unknown>;

    // #128: Verify proof on the status list credential before trusting it
    if (options.didResolver) {
      const proofCheck = await verifyDataIntegrity(
        statusListVC as unknown as VerifiableCredential,
        options.didResolver,
      );
      if (!proofCheck.passed) {
        return {
          name: "bitstringStatus",
          passed: false,
          detail: `Status list credential proof invalid: ${proofCheck.detail ?? "verification failed"}`,
        };
      }
    }

    const subject = statusListVC["credentialSubject"] as Record<string, unknown> | undefined;
    if (!subject) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Status list credential missing credentialSubject",
      };
    }

    const encodedList = subject["encodedList"] as string | undefined;
    if (!encodedList) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Status list credential missing encodedList",
      };
    }

    // Decode the base64-encoded, GZIP-compressed bitstring
    const compressed = Buffer.from(encodedList, "base64");

    // #127: Reject compressed data exceeding size limit to prevent decompression bombs
    if (compressed.length > MAX_COMPRESSED_SIZE) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Compressed encodedList exceeds maximum size (${MAX_COMPRESSED_SIZE} bytes)`,
      };
    }

    // #126: Use async gunzip instead of blocking gunzipSync
    const bitstring = await gunzip(compressed);

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    if (byteIndex >= bitstring.length) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `statusListIndex ${index} out of range`,
      };
    }

    // Bits are MSB-first within each byte
    const isRevoked = (bitstring[byteIndex] & (0x80 >> bitIndex)) !== 0;

    if (isRevoked) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Credential revoked (statusListIndex: ${index})`,
      };
    }

    return { name: "bitstringStatus", passed: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unable to check BitstringStatusList";
    return {
      name: "bitstringStatus",
      passed: false,
      detail: message,
    };
  }
}

// Export for testing
export {
  validateStatusListUrl as _validateStatusListUrl,
  MAX_COMPRESSED_SIZE,
};
