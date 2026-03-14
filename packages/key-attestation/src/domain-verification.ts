/**
 * Domain Verification for OpenCred Key Attestation.
 *
 * Verifies domain ownership before OpenCred attests an issuer's public key.
 * Supports DNS TXT record verification and HTTP well-known challenge verification.
 *
 * Security considerations:
 * - Challenge tokens use CSPRNG (crypto.randomBytes)
 * - DNS verification queries multiple resolvers to mitigate cache poisoning
 * - HTTP verification enforces HTTPS-only and rejects private/loopback IPs (SSRF prevention)
 * - Challenge tokens and secrets are never logged
 */

import { randomBytes, randomUUID } from "node:crypto";
import dns from "node:dns";
import { isIP } from "node:net";
import { AttestationError } from "@opencred/shared";
import type { IdentityVerificationMethod } from "./types.js";

// ─── Constants ────────────────────────────────────────────────────────

const CHALLENGE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const HTTP_TIMEOUT_MS = 10_000; // 10 seconds
const TOKEN_BYTES = 32; // 256-bit entropy
const WELL_KNOWN_PATH = ".well-known/opencred-challenge";
const DNS_TXT_PREFIX = "opencred-verify=";

// ─── Challenge Types ──────────────────────────────────────────────────

/** A domain ownership challenge awaiting verification. */
export interface DomainChallenge {
  /** Unique challenge identifier. */
  id: string;
  /** The domain being verified. */
  domain: string;
  /** Verification method (dns-txt or http-challenge). */
  method: IdentityVerificationMethod;
  /** The secret token the domain owner must publish. */
  token: string;
  /** When this challenge expires. */
  expiresAt: Date;
  /** When this challenge was created. */
  createdAt: Date;
  /** Whether the challenge has been successfully verified. */
  verified: boolean;
}

/** Details returned to the caller after challenge generation. */
export interface ChallengeDetails {
  /** Unique challenge identifier. */
  challengeId: string;
  /** The domain being verified. */
  domain: string;
  /** Verification method. */
  method: IdentityVerificationMethod;
  /** The secret token to publish. */
  token: string;
  /** When this challenge expires. */
  expiresAt: Date;
  /** DNS TXT record value (for dns-txt method) or URL to publish at (for http-challenge). */
  instructions: string;
}

/** Result of a domain verification attempt. */
export interface DomainVerificationResult {
  /** Whether the domain ownership was verified. */
  verified: boolean;
  /** The domain that was being verified. */
  domain: string;
  /** The verification method used. */
  method: IdentityVerificationMethod;
  /** ISO timestamp of verification (only present if verified). */
  verifiedAt?: string;
  /** Error message (only present if verification failed). */
  error?: string;
}

// ─── Challenge Store ──────────────────────────────────────────────────

/**
 * In-memory challenge store with TTL-based expiry.
 *
 * Stores pending domain verification challenges and automatically
 * cleans up expired entries.
 */
export class DomainChallengeStore {
  private readonly challenges = new Map<string, DomainChallenge>();

  /** Create and store a new challenge. */
  create(
    domain: string,
    method: IdentityVerificationMethod,
    token: string,
  ): DomainChallenge {
    const now = new Date();
    const challenge: DomainChallenge = {
      id: randomUUID(),
      domain,
      method,
      token,
      createdAt: now,
      expiresAt: new Date(now.getTime() + CHALLENGE_TTL_MS),
      verified: false,
    };
    this.challenges.set(challenge.id, challenge);
    return challenge;
  }

  /** Retrieve a challenge by ID. Returns undefined if not found or expired. */
  get(id: string): DomainChallenge | undefined {
    const challenge = this.challenges.get(id);
    if (!challenge) return undefined;
    if (challenge.expiresAt <= new Date()) {
      this.challenges.delete(id);
      return undefined;
    }
    return challenge;
  }

  /** Delete a challenge by ID. */
  delete(id: string): boolean {
    return this.challenges.delete(id);
  }

  /** Remove all expired challenges. Returns the count of removed entries. */
  cleanup(): number {
    const now = new Date();
    let removed = 0;
    for (const [id, challenge] of this.challenges) {
      if (challenge.expiresAt <= now) {
        this.challenges.delete(id);
        removed++;
      }
    }
    return removed;
  }

  /** Return the number of active (non-expired) challenges. */
  get size(): number {
    return this.challenges.size;
  }
}

// ─── Challenge Generation ─────────────────────────────────────────────

/**
 * Generate a domain ownership challenge.
 *
 * Creates a cryptographically random token that the domain owner must
 * publish at the appropriate location (DNS TXT record or HTTP endpoint).
 */
export function generateChallenge(
  domain: string,
  method: IdentityVerificationMethod,
): ChallengeDetails {
  validateDomain(domain);
  validateMethod(method);

  const token = randomBytes(TOKEN_BYTES).toString("hex");
  const challengeId = randomUUID();
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);

  let instructions: string;
  if (method === "dns-txt") {
    instructions = `Add a DNS TXT record to ${domain} with value: ${DNS_TXT_PREFIX}${token}`;
  } else {
    instructions = `Place the token at https://${domain}/${WELL_KNOWN_PATH}/${challengeId}`;
  }

  return {
    challengeId,
    domain,
    method,
    token,
    expiresAt,
    instructions,
  };
}

// ─── DNS TXT Verification ─────────────────────────────────────────────

/**
 * Verify a DNS TXT challenge by querying for the expected token.
 *
 * Queries multiple DNS resolvers (system default + Google Public DNS)
 * to mitigate DNS cache poisoning attacks. The challenge is only
 * considered verified if ALL resolvers return the expected record.
 */
export async function verifyDnsTxtChallenge(
  domain: string,
  expectedToken: string,
): Promise<boolean> {
  validateDomain(domain);
  if (!expectedToken) {
    throw new AttestationError("Expected token is required for DNS verification");
  }

  const expectedValue = `${DNS_TXT_PREFIX}${expectedToken}`;

  // Query system default resolver
  const defaultResult = await queryDnsTxt(domain, expectedValue);

  // Query Google Public DNS (8.8.8.8) as a second resolver
  const googleResult = await queryDnsTxtWithResolver(domain, expectedValue, "8.8.8.8");

  // Both resolvers must confirm the record
  return defaultResult && googleResult;
}

/**
 * Query DNS TXT records using the system default resolver.
 */
async function queryDnsTxt(
  domain: string,
  expectedValue: string,
): Promise<boolean> {
  try {
    const records = await dns.promises.resolveTxt(domain);
    return matchesTxtRecord(records, expectedValue);
  } catch {
    return false;
  }
}

/**
 * Query DNS TXT records using a specific resolver address.
 */
async function queryDnsTxtWithResolver(
  domain: string,
  expectedValue: string,
  resolverAddress: string,
): Promise<boolean> {
  try {
    const resolver = new dns.Resolver();
    resolver.setServers([resolverAddress]);

    const records = await new Promise<string[][]>((resolve, reject) => {
      resolver.resolveTxt(domain, (err, addresses) => {
        if (err) reject(err);
        else resolve(addresses);
      });
    });

    return matchesTxtRecord(records, expectedValue);
  } catch {
    return false;
  }
}

/**
 * Check if any TXT record matches the expected value.
 * DNS TXT records are returned as arrays of strings (chunks).
 */
function matchesTxtRecord(records: string[][], expectedValue: string): boolean {
  for (const record of records) {
    // TXT records may be split into chunks; concatenate them
    const joined = record.join("");
    if (joined === expectedValue) {
      return true;
    }
  }
  return false;
}

// ─── HTTP Challenge Verification ──────────────────────────────────────

/** IPv4 private/loopback prefixes for SSRF prevention. */
const PRIVATE_IPV4_PREFIXES = ["10.", "127.", "0.", "169.254."] as const;

/**
 * Check if an IPv4 address falls within private/reserved ranges.
 */
function isPrivateIPv4(ip: string): boolean {
  // Simple prefix checks
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
 */
function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  // Loopback
  if (normalized === "::1") return true;
  // Unique local (fc00::/7 covers fc00:: through fdff::)
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  // Link-local
  if (normalized.startsWith("fe80:")) return true;
  return false;
}

/**
 * Check if an IP address is private or loopback (SSRF prevention).
 */
export function isPrivateIP(ip: string): boolean {
  if (isIP(ip) === 4) return isPrivateIPv4(ip);
  if (isIP(ip) === 6) return isPrivateIPv6(ip);
  return false;
}

/**
 * Verify an HTTP challenge by fetching the well-known URL.
 *
 * Security:
 * - HTTPS only (no HTTP fallback)
 * - Resolves domain first and rejects private/loopback IPs (SSRF prevention)
 * - 10-second timeout
 */
export async function verifyHttpChallenge(
  domain: string,
  challengeId: string,
  expectedToken: string,
): Promise<boolean> {
  validateDomain(domain);
  if (!challengeId) {
    throw new AttestationError("Challenge ID is required for HTTP verification");
  }
  if (!expectedToken) {
    throw new AttestationError("Expected token is required for HTTP verification");
  }

  // SSRF prevention: resolve domain and reject private IPs
  try {
    const addresses = await dns.promises.resolve4(domain);
    for (const addr of addresses) {
      if (isPrivateIP(addr)) {
        throw new AttestationError(
          "Domain resolves to a private or loopback IP address",
        );
      }
    }
  } catch (err) {
    if (err instanceof AttestationError) throw err;
    // Also try IPv6
    try {
      const addresses = await dns.promises.resolve6(domain);
      for (const addr of addresses) {
        if (isPrivateIP(addr)) {
          throw new AttestationError(
            "Domain resolves to a private or loopback IP address",
          );
        }
      }
    } catch (innerErr) {
      if (innerErr instanceof AttestationError) throw innerErr;
      throw new AttestationError("Failed to resolve domain for SSRF check");
    }
  }

  // Fetch the challenge URL (HTTPS only)
  const url = `https://${domain}/${WELL_KNOWN_PATH}/${challengeId}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);

    try {
      const response = await fetch(url, {
        method: "GET",
        signal: controller.signal,
        redirect: "error", // Don't follow redirects (potential SSRF vector)
      });

      if (!response.ok) return false;

      const body = (await response.text()).trim();
      return body === expectedToken;
    } finally {
      clearTimeout(timeoutId);
    }
  } catch {
    return false;
  }
}

// ─── High-Level Verification ──────────────────────────────────────────

/**
 * Verify domain ownership using a previously generated challenge.
 *
 * Retrieves the challenge from the store, dispatches to the appropriate
 * verifier (DNS TXT or HTTP), and returns the result.
 */
export async function verifyDomainOwnership(
  challengeId: string,
  store: DomainChallengeStore,
): Promise<DomainVerificationResult> {
  if (!challengeId) {
    return {
      verified: false,
      domain: "",
      method: "dns-txt",
      error: "Challenge ID is required",
    };
  }

  const challenge = store.get(challengeId);
  if (!challenge) {
    return {
      verified: false,
      domain: "",
      method: "dns-txt",
      error: "Challenge not found or expired",
    };
  }

  if (challenge.verified) {
    return {
      verified: false,
      domain: challenge.domain,
      method: challenge.method,
      error: "Challenge has already been verified",
    };
  }

  let verified: boolean;
  try {
    if (challenge.method === "dns-txt") {
      verified = await verifyDnsTxtChallenge(challenge.domain, challenge.token);
    } else {
      verified = await verifyHttpChallenge(
        challenge.domain,
        challenge.id,
        challenge.token,
      );
    }
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Verification failed";
    return {
      verified: false,
      domain: challenge.domain,
      method: challenge.method,
      error: message,
    };
  }

  if (verified) {
    challenge.verified = true;
    const verifiedAt = new Date().toISOString();
    return {
      verified: true,
      domain: challenge.domain,
      method: challenge.method,
      verifiedAt,
    };
  }

  return {
    verified: false,
    domain: challenge.domain,
    method: challenge.method,
    error: "Domain verification failed: expected record or response not found",
  };
}

// ─── Validation Helpers ───────────────────────────────────────────────

/**
 * Validate a domain name.
 * Rejects empty strings, domains with protocols, and overly long domains.
 */
function validateDomain(domain: string): void {
  if (!domain) {
    throw new AttestationError("Domain is required");
  }
  if (domain.includes("://")) {
    throw new AttestationError("Domain must not include a protocol (e.g., https://)");
  }
  if (domain.includes("/")) {
    throw new AttestationError("Domain must not include a path");
  }
  if (domain.length > 253) {
    throw new AttestationError("Domain name exceeds maximum length (253 characters)");
  }
}

/**
 * Validate the verification method.
 */
function validateMethod(method: IdentityVerificationMethod): void {
  if (method !== "dns-txt" && method !== "http-challenge") {
    throw new AttestationError(
      `Invalid verification method: ${method}. Must be 'dns-txt' or 'http-challenge'`,
    );
  }
}
