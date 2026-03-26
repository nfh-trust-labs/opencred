/**
 * SSRF (Server-Side Request Forgery) prevention utilities.
 *
 * Validates that resolved IP addresses are public and not within
 * private, loopback, or link-local ranges. Used by the did:web
 * resolver to prevent fetching DID documents from internal networks.
 */

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

  return false;
}

/**
 * Check if an IPv6 address is private/loopback.
 *
 * Covers:
 * - ::1 (loopback)
 * - fc00::/7 (unique local, covers fc00:: through fdff::)
 * - fe80::/10 (link-local)
 */
function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === "::1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (normalized.startsWith("fe80:")) return true;

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
