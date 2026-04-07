/**
 * SSRF (Server-Side Request Forgery) prevention utilities.
 *
 * Validates that resolved IP addresses are public and not within
 * private, loopback, or link-local ranges. Used by the did:web
 * resolver to prevent fetching DID documents from internal networks.
 *
 * Also provides DNS-resolution + IP-pinning helpers that prevent
 * DNS-rebinding (TOCTOU) attacks by resolving the hostname to an IP
 * BEFORE the fetch and connecting directly to the resolved IP rather
 * than allowing the HTTP client to re-resolve the hostname.
 */

import { resolve4, resolve6 } from "node:dns/promises";
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

/** Predicate for classifying an IP as private/reserved. */
export type IsPrivateIPPredicate = (ip: string) => boolean;

/** Result of resolving and pinning a hostname to a public IP. */
export interface PinnedHostnameResult {
  /** The IP address the hostname resolved to. */
  address: string;
  /** The IP family (4 for IPv4, 6 for IPv6). */
  family: 4 | 6;
}

/** Options for {@link resolveAndPinHostname}. */
export interface ResolveAndPinOptions {
  /**
   * Optional override for the private-IP predicate.
   * Defaults to the shared {@link isPrivateIP} implementation.
   */
  isPrivateIP?: IsPrivateIPPredicate;
}

/**
 * Resolve a hostname to an IP and validate that ALL resolved IPs are public.
 *
 * This is the core defence against DNS-rebinding (TOCTOU) attacks: we
 * resolve the hostname ourselves up-front, validate every returned address,
 * and return the first one. Callers must then issue the request directly
 * against the returned IP (not the original hostname) so the HTTP client
 * cannot re-resolve the hostname to a different (private) address between
 * the validation and the fetch.
 *
 * Uses `dns.resolve4` / `dns.resolve6` rather than `dns.lookup`, because
 * `dns.lookup` returns only a single address from `getaddrinfo` and can
 * leave additional records unchecked.
 *
 * @param hostname - The hostname to resolve (no scheme, no port).
 * @param options - Optional predicate override.
 * @returns The first resolved address and its family.
 * @throws Error when DNS resolution fails or when ANY resolved IP is private.
 */
export async function resolveAndPinHostname(
  hostname: string,
  options: ResolveAndPinOptions = {},
): Promise<PinnedHostnameResult> {
  const predicate = options.isPrivateIP ?? isPrivateIP;

  // Resolve both IPv4 and IPv6 records, matching the existing
  // checkBitstringStatusList behaviour. We must check every record so a
  // multi-record DNS response cannot smuggle a private IP past us.
  const [v4Result, v6Result] = await Promise.allSettled([
    resolve4(hostname),
    resolve6(hostname),
  ]);

  const v4Addresses = v4Result.status === "fulfilled" ? v4Result.value : [];
  const v6Addresses = v6Result.status === "fulfilled" ? v6Result.value : [];

  if (v4Addresses.length === 0 && v6Addresses.length === 0) {
    throw new Error(`DNS resolution failed for ${hostname}`);
  }

  // Validate ALL resolved addresses up-front. If any are private, refuse the
  // entire request — we cannot tell which one the OS resolver would return
  // when the underlying fetch re-resolves the hostname.
  for (const addr of [...v4Addresses, ...v6Addresses]) {
    if (predicate(addr)) {
      throw new Error(`DNS resolved to private/reserved IP for ${hostname}`);
    }
  }

  // Prefer IPv4 when available, fall back to IPv6.
  if (v4Addresses.length > 0) {
    return { address: v4Addresses[0], family: 4 };
  }
  return { address: v6Addresses[0], family: 6 };
}

/**
 * Build a URL whose hostname has been replaced with a pre-resolved IP, plus
 * the matching headers (with the original hostname in `Host`) so the server
 * can route the request via virtual hosting / SNI.
 *
 * The returned URL is what callers should pass to `fetch` to defeat DNS
 * rebinding — once the URL contains a literal IP, the HTTP client cannot
 * re-resolve the hostname to a different (private) address.
 *
 * @param originalUrl - The original URL (with hostname).
 * @param pinned - The result from {@link resolveAndPinHostname}.
 * @returns The pinned URL string and the matching headers.
 */
export function buildPinnedFetchTarget(
  originalUrl: string,
  pinned: PinnedHostnameResult,
): { url: string; headers: Record<string, string> } {
  const parsed = new URL(originalUrl);

  // Capture the original `host` (includes a non-default port) BEFORE we
  // mutate `hostname`. URL drops the port from `host` when it equals the
  // default for the scheme, which is exactly the behaviour we want for the
  // Host header per RFC 7230 §5.4.
  const originalHost = parsed.host;

  if (pinned.family === 6) {
    parsed.hostname = `[${pinned.address}]`;
  } else {
    parsed.hostname = pinned.address;
  }

  return {
    url: parsed.toString(),
    headers: {
      Host: originalHost,
    },
  };
}
