/**
 * SSRF (Server-Side Request Forgery) prevention utilities.
 *
 * Validates that resolved IP addresses are public and not within
 * private, loopback, or link-local ranges. Used by the did:web
 * resolver to prevent fetching DID documents from internal networks.
 */

import { promises as dns } from "node:dns";
import { isIP } from "node:net";

/** IPv4 private/loopback prefixes for SSRF prevention. */
const PRIVATE_IPV4_PREFIXES = ["10.", "127.", "0.", "169.254."] as const;

/**
 * Check if an IPv4 address falls within private/reserved ranges.
 *
 * Covers:
 * - 10.0.0.0/8 (RFC 1918)
 * - 127.0.0.0/8 (loopback)
 * - 0.0.0.0/8 (reserved)
 * - 169.254.0.0/16 (link-local)
 * - 172.16.0.0/12 (RFC 1918)
 * - 192.168.0.0/16 (RFC 1918)
 * - 100.64.0.0/10 (CGNAT, RFC 6598)
 * - 198.18.0.0/15 (benchmarking, RFC 2544)
 * - 224.0.0.0/4 (multicast)
 * - 240.0.0.0/4 (reserved for future use)
 * - 255.255.255.255 (broadcast)
 */
function isPrivateIPv4(ip: string): boolean {
  for (const prefix of PRIVATE_IPV4_PREFIXES) {
    if (ip.startsWith(prefix)) return true;
  }

  // 172.16.0.0 - 172.31.255.255
  if (ip.startsWith("172.")) {
    const secondOctet = parseInt(ip.split(".")[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }

  // 192.168.0.0/16
  if (ip.startsWith("192.168.")) return true;

  // 100.64.0.0/10 — CGNAT (RFC 6598): 100.64.0.0 - 100.127.255.255
  if (ip.startsWith("100.")) {
    const secondOctet = parseInt(ip.split(".")[1], 10);
    if (secondOctet >= 64 && secondOctet <= 127) return true;
  }

  // 198.18.0.0/15 — benchmarking (RFC 2544): 198.18.0.0 - 198.19.255.255
  if (ip.startsWith("198.18.") || ip.startsWith("198.19.")) return true;

  // 224.0.0.0/4 (multicast) + 240.0.0.0/4 (reserved) + 255.255.255.255 (broadcast)
  const firstOctet = parseInt(ip.split(".")[0], 10);
  if (firstOctet >= 224) return true;

  return false;
}

/**
 * Check if an IPv6 address is private/loopback.
 *
 * Covers:
 * - ::1 (loopback)
 * - :: (unspecified)
 * - fc00::/7 (unique local, covers fc00:: through fdff::)
 * - fe80::/10 (link-local)
 * - ff00::/8 (multicast)
 * - 0100::/64 (discard prefix, RFC 6666)
 */
function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === "::1") return true;
  if (normalized === "::") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (normalized.startsWith("fe80:")) return true;
  if (normalized.startsWith("ff")) return true;
  if (normalized.startsWith("0100:")) return true;

  // IPv4-mapped IPv6 — two forms:
  // 1. Dotted: ::ffff:192.168.1.1
  // 2. Hex:    ::ffff:c0a8:0101
  const dottedMatch = normalized.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dottedMatch) return isPrivateIPv4(dottedMatch[1]);

  const hexMatch = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexMatch) {
    const hi = parseInt(hexMatch[1], 16);
    const lo = parseInt(hexMatch[2], 16);
    const a = (hi >> 8) & 0xff;
    const b = hi & 0xff;
    const c = (lo >> 8) & 0xff;
    const d = lo & 0xff;
    return isPrivateIPv4(`${a}.${b}.${c}.${d}`);
  }

  return false;
}

/**
 * Check if an IP address is private, loopback, or link-local.
 *
 * Used for SSRF prevention: domains that resolve to non-public IPs
 * must be rejected when fetching DID documents or other resources.
 *
 * @param ip - IPv4 or IPv6 address string
 * @returns true if the IP is private/loopback/link-local, false otherwise
 */
export function isPrivateIP(ip: string): boolean {
  if (isIP(ip) === 4) return isPrivateIPv4(ip);
  if (isIP(ip) === 6) return isPrivateIPv6(ip);
  return false;
}

/**
 * DNS error codes that indicate "no records of this type exist" —
 * benign for AAAA lookups since most hosts lack IPv6 records.
 * Any other error (ETIMEOUT, ESERVFAIL, ECONNREFUSED, etc.) is
 * treated as a transient failure and triggers fail-closed behavior.
 */
const BENIGN_DNS_CODES = new Set(["ENODATA", "ENOTFOUND"]);

/**
 * Resolve a hostname's DNS records and validate all returned IPs
 * against SSRF protections. Fail-closed: if DNS resolution encounters
 * a non-benign error, the request is blocked.
 *
 * Resolution strategy:
 * - Both A and AAAA are resolved concurrently via `Promise.allSettled`
 * - ENODATA/ENOTFOUND on either lookup = "no records of that type" (benign)
 * - Any other DNS error (ETIMEOUT, ESERVFAIL, etc.) = fail-closed (blocked)
 * - If both lookups produce no addresses (both benign failures) = blocked
 * - Every resolved IP is checked against private/reserved ranges
 *
 * @param hostname - The hostname to resolve (not a literal IP)
 * @returns Array of resolved public IP addresses
 * @throws Error if DNS fails, returns no addresses, or any IP is private
 */
export async function resolveDnsForSsrf(hostname: string): Promise<string[]> {
  const [v4Result, v6Result] = await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolve6(hostname),
  ]);

  // Check for non-benign DNS errors (transient failures → fail-closed)
  if (v4Result.status === "rejected" && !isBenignDnsError(v4Result.reason)) {
    throw new Error(
      `DNS A lookup failed for ${hostname}: ${getDnsErrorCode(v4Result.reason)}`,
    );
  }
  if (v6Result.status === "rejected" && !isBenignDnsError(v6Result.reason)) {
    throw new Error(
      `DNS AAAA lookup failed for ${hostname}: ${getDnsErrorCode(v6Result.reason)}`,
    );
  }

  const addresses = [
    ...(v4Result.status === "fulfilled" ? v4Result.value : []),
    ...(v6Result.status === "fulfilled" ? v6Result.value : []),
  ];

  if (addresses.length === 0) {
    throw new Error(`DNS resolution returned no addresses for ${hostname}`);
  }

  for (const ip of addresses) {
    if (isPrivateIP(ip)) {
      throw new Error(
        `SSRF protection: ${hostname} resolves to private/reserved IP`,
      );
    }
  }

  return addresses;
}

function isBenignDnsError(error: unknown): boolean {
  const code = getDnsErrorCode(error);
  return code !== undefined && BENIGN_DNS_CODES.has(code);
}

function getDnsErrorCode(error: unknown): string | undefined {
  if (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    typeof (error as { code: unknown }).code === "string"
  ) {
    return (error as { code: string }).code;
  }
  return undefined;
}
