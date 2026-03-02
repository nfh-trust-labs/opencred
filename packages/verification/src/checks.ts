import { promisify } from "node:util";
import { gunzip as gunzipCb } from "node:zlib";
import type { DeDiClient } from "@opencred/dedi-client";
import { computeRevocationHash } from "@opencred/crypto";
import type { DIDResolver } from "@opencred/did";
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

/**
 * Check whether an IPv4 or IPv6 address is private / reserved.
 * Rejects: 10.x, 172.16-31.x, 192.168.x, 127.x, 0.x, 169.254.x (link-local),
 * ::1, fe80::/10, fc00::/7, and other reserved ranges.
 */
function isPrivateIP(ip: string): boolean {
  // IPv4
  if (ip.includes(".")) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
      return true; // malformed → treat as private
    }
    const [a, b] = parts;
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 127) return true; // 127.0.0.0/8
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 (link-local)
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
    if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15
    if (a >= 224 && a <= 239) return true; // 224.0.0.0/4 (multicast)
    if (a >= 240) return true; // 240.0.0.0/4 (reserved)
    return false;
  }

  // IPv6
  const normalized = ip.toLowerCase().replace(/^\[|]$/g, "");
  if (normalized === "::1") return true;
  if (normalized === "::") return true;
  if (normalized.startsWith("fe80:") || normalized.startsWith("fe8") || normalized === "fe80::") {
    return true;
  }
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (normalized.startsWith("::ffff:")) {
    const ipv4Part = normalized.slice(7);
    if (ipv4Part.includes(".")) {
      return isPrivateIP(ipv4Part);
    }
  }
  return false;
}

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
): { valid: true; url: string } | { valid: false; detail: string } {
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

  // Check if hostname is a raw IP literal (IPv4 or bracketed IPv6)
  const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const isIPv6 = hostname.startsWith("[") || hostname.includes(":");
  if ((isIPv4 || isIPv6) && isPrivateIP(hostname)) {
    return { valid: false, detail: "Status list URL points to a private/reserved IP" };
  }

  if (allowedDomains && allowedDomains.length > 0) {
    const allowed = allowedDomains.some(
      (d) => hostname === d.toLowerCase() || hostname.endsWith(`.${d.toLowerCase()}`),
    );
    if (!allowed) {
      return { valid: false, detail: "Status list URL domain is not on the allowlist" };
    }
  }

  return { valid: true, url: parsed.toString() };
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

    const response = await globalThis.fetch(urlValidation.url, {
      redirect: "error", // Prevent redirect-based SSRF
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
  } catch {
    return {
      name: "bitstringStatus",
      passed: false,
      detail: "Unable to check BitstringStatusList",
    };
  }
}

// Export for testing
export { isPrivateIP as _isPrivateIP, validateStatusListUrl as _validateStatusListUrl, MAX_COMPRESSED_SIZE };
