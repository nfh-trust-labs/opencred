import { Hono } from "hono";
import { z } from "zod";
import { randomBytes } from "node:crypto";
import { promises as dns } from "node:dns";
import { ValidationError, VerificationError, NotFoundError } from "@opencred/shared";
import { TTLStore } from "@opencred/state";

// --- Constants ---

/** 24 hours in milliseconds */
const CHALLENGE_TTL_MS = 24 * 60 * 60 * 1000;

/** Token length in bytes (256-bit entropy = 32 bytes) */
const TOKEN_BYTES = 32;

/** DNS TXT record prefix */
const DNS_TXT_PREFIX = "opencred-verify=";

/** DNS subdomain label for verification */
const DNS_SUBDOMAIN = "_opencred-verify";

/** Well-known path for HTTP challenge */
const HTTP_WELL_KNOWN_PATH = ".well-known/opencred-challenge";

/**
 * Multiple DNS resolvers for cache poisoning mitigation.
 * Using well-known public resolvers.
 */
const DNS_RESOLVERS = [
  "8.8.8.8", // Google
  "1.1.1.1", // Cloudflare
  "9.9.9.9", // Quad9
];

/** Minimum number of resolvers that must agree for DNS verification */
const DNS_MIN_AGREEMENT = 2;

// --- Private IP ranges for SSRF prevention ---

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
    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 127.0.0.0/8 (loopback)
    if (a === 127) return true;
    // 0.0.0.0/8
    if (a === 0) return true;
    // 169.254.0.0/16 (link-local)
    if (a === 169 && b === 254) return true;
    // 100.64.0.0/10 (Carrier-grade NAT / shared address space)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 198.18.0.0/15 (benchmarking)
    if (a === 198 && (b === 18 || b === 19)) return true;
    // 224.0.0.0/4 (multicast)
    if (a >= 224 && a <= 239) return true;
    // 240.0.0.0/4 (reserved)
    if (a >= 240) return true;
    return false;
  }

  // IPv6
  const normalized = ip.toLowerCase().replace(/^\[|]$/g, "");

  // ::1 (loopback)
  if (normalized === "::1") return true;
  // :: (unspecified)
  if (normalized === "::") return true;
  // fe80::/10 (link-local)
  if (normalized.startsWith("fe80:") || normalized.startsWith("fe8") || normalized === "fe80::") {
    return true;
  }
  // fc00::/7 (unique local address)
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  // ::ffff:0:0/96 (IPv4-mapped IPv6) — extract the embedded IPv4 and check it
  if (normalized.startsWith("::ffff:")) {
    const ipv4Part = normalized.slice(7);
    if (ipv4Part.includes(".")) {
      return isPrivateIP(ipv4Part);
    }
  }

  return false;
}

// --- Types ---

export type ChallengeMethod = "dns-txt" | "http-challenge";

export interface ChallengeRecord {
  id: string;
  domain: string;
  method: ChallengeMethod;
  token: string;
  createdAt: string;
  expiresAt: string;
  verified: boolean;
  verifiedAt?: string;
}

// --- Zod schemas ---

const domainRegex = /^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/;

const initiateChallengeSchema = z.object({
  domain: z
    .string()
    .min(1, "domain is required")
    .refine((d) => domainRegex.test(d), "domain must be a valid domain name"),
  method: z.enum(["dns-txt", "http-challenge"], {
    errorMap: () => ({ message: "method must be 'dns-txt' or 'http-challenge'" }),
  }),
});

const confirmChallengeSchema = z.object({
  challengeId: z.string().min(1, "challengeId is required"),
});

// --- Dependencies ---

export interface DomainVerificationDeps {
  /** TTL store for challenge state. If not provided, a module-scoped default is created. */
  challengeStore?: TTLStore<ChallengeRecord>;
  /** DNS resolver function — injectable for testing */
  dnsResolveTxt?: (hostname: string, resolverIp: string) => Promise<string[][]>;
  /** HTTP fetch function — injectable for testing */
  httpFetch?: (url: string) => Promise<{ ok: boolean; text: () => Promise<string> }>;
  /** DNS resolve4 — injectable for testing (returns IPv4 addresses for SSRF check) */
  dnsResolve4?: (hostname: string) => Promise<string[]>;
  /** DNS resolve6 — injectable for testing (returns IPv6 addresses for SSRF check) */
  dnsResolve6?: (hostname: string) => Promise<string[]>;
}

// --- Default implementations ---

/**
 * Default DNS TXT resolver that uses a specific resolver IP.
 * Creates a fresh Resolver instance pointed at the given server.
 */
async function defaultDnsResolveTxt(hostname: string, resolverIp: string): Promise<string[][]> {
  const resolver = new dns.Resolver();
  resolver.setServers([resolverIp]);
  return resolver.resolveTxt(hostname);
}

/**
 * Default DNS resolve4 for SSRF IP validation.
 */
async function defaultDnsResolve4(hostname: string): Promise<string[]> {
  return dns.resolve4(hostname);
}

/**
 * Default DNS resolve6 for SSRF IP validation.
 */
async function defaultDnsResolve6(hostname: string): Promise<string[]> {
  try {
    return await dns.resolve6(hostname);
  } catch {
    // No AAAA records is not an error for our purpose
    return [];
  }
}

/**
 * Default HTTP fetch using the global fetch API.
 */
async function defaultHttpFetch(
  url: string,
): Promise<{ ok: boolean; text: () => Promise<string> }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const resp = await fetch(url, {
      signal: controller.signal,
      redirect: "error", // do not follow redirects — SSRF mitigation
    });
    return resp;
  } finally {
    clearTimeout(timeout);
  }
}

// --- Helpers ---

/**
 * Generate a cryptographically secure random token with 256-bit entropy.
 * Returns a hex-encoded string (64 chars).
 */
function generateToken(): string {
  return randomBytes(TOKEN_BYTES).toString("hex");
}

/**
 * Generate a unique challenge ID (also crypto-random).
 */
function generateChallengeId(): string {
  return `ch_${randomBytes(16).toString("hex")}`;
}

/**
 * Verify a DNS TXT challenge by querying multiple resolvers.
 * Returns true only if at least DNS_MIN_AGREEMENT resolvers find the token.
 */
async function verifyDnsChallenge(
  domain: string,
  token: string,
  resolveTxt: (hostname: string, resolverIp: string) => Promise<string[][]>,
): Promise<{ verified: boolean; detail?: string }> {
  const lookupHost = `${DNS_SUBDOMAIN}.${domain}`;
  const expectedValue = `${DNS_TXT_PREFIX}${token}`;

  let matchCount = 0;
  let queryCount = 0;
  const errors: string[] = [];

  for (const resolverIp of DNS_RESOLVERS) {
    try {
      const records = await resolveTxt(lookupHost, resolverIp);
      queryCount++;
      // TXT records are arrays of arrays (each record is an array of chunks)
      const flatRecords = records.map((chunks) => chunks.join(""));
      if (flatRecords.includes(expectedValue)) {
        matchCount++;
      }
    } catch {
      errors.push(`Resolver ${resolverIp} failed`);
    }
  }

  if (queryCount === 0) {
    return { verified: false, detail: "All DNS resolvers failed" };
  }

  if (matchCount >= DNS_MIN_AGREEMENT) {
    return { verified: true };
  }

  return {
    verified: false,
    detail: `DNS TXT record not found (${matchCount}/${queryCount} resolvers matched, need ${DNS_MIN_AGREEMENT})`,
  };
}

/**
 * Verify an HTTP challenge by fetching the well-known URL.
 * Includes SSRF prevention: validates that resolved IPs are public.
 */
async function verifyHttpChallenge(
  domain: string,
  token: string,
  httpFetch: (url: string) => Promise<{ ok: boolean; text: () => Promise<string> }>,
  resolve4: (hostname: string) => Promise<string[]>,
  resolve6: (hostname: string) => Promise<string[]>,
): Promise<{ verified: boolean; detail?: string }> {
  // SSRF prevention: resolve the domain and validate all IPs are public
  let ipv4Addrs: string[] = [];
  let ipv6Addrs: string[] = [];

  try {
    ipv4Addrs = await resolve4(domain);
  } catch {
    // No A records — may have only AAAA
  }

  try {
    ipv6Addrs = await resolve6(domain);
  } catch {
    // No AAAA records
  }

  const allAddrs = [...ipv4Addrs, ...ipv6Addrs];
  if (allAddrs.length === 0) {
    return { verified: false, detail: "Domain does not resolve to any IP address" };
  }

  for (const ip of allAddrs) {
    if (isPrivateIP(ip)) {
      return {
        verified: false,
        detail: "Domain resolves to a private or reserved IP address",
      };
    }
  }

  // Fetch the challenge URL
  const url = `https://${domain}/${HTTP_WELL_KNOWN_PATH}/${token}`;
  try {
    const response = await httpFetch(url);
    if (!response.ok) {
      return { verified: false, detail: "HTTP challenge endpoint returned a non-200 response" };
    }
    const body = await response.text();
    if (body.trim() === token) {
      return { verified: true };
    }
    return {
      verified: false,
      detail: "HTTP challenge response does not contain the expected token",
    };
  } catch {
    return { verified: false, detail: "Failed to fetch HTTP challenge URL" };
  }
}

// --- Factory ---

export function createDomainVerificationRoutes(deps: DomainVerificationDeps = {}) {
  const challengeStore =
    deps.challengeStore ?? new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 60_000);
  const resolveTxt = deps.dnsResolveTxt ?? defaultDnsResolveTxt;
  const httpFetch = deps.httpFetch ?? defaultHttpFetch;
  const resolve4 = deps.dnsResolve4 ?? defaultDnsResolve4;
  const resolve6 = deps.dnsResolve6 ?? defaultDnsResolve6;

  const domainVerify = new Hono();

  // POST /domain-verify — initiate a challenge
  domainVerify.post("/domain-verify", async (c) => {
    const rawBody = await c.req.json();
    const parsed = initiateChallengeSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const { domain, method } = parsed.data;

    // Generate challenge token (256-bit CSPRNG)
    const token = generateToken();
    const challengeId = generateChallengeId();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + CHALLENGE_TTL_MS);

    // Build instructions based on method
    let challenge: string;
    let instructions: string;

    if (method === "dns-txt") {
      challenge = `${DNS_TXT_PREFIX}${token}`;
      instructions =
        `Add a DNS TXT record to ${DNS_SUBDOMAIN}.${domain} ` + `with the value: ${challenge}`;
    } else {
      challenge = token;
      instructions =
        `Place a file at https://${domain}/${HTTP_WELL_KNOWN_PATH}/${token} ` +
        `containing exactly the token value: ${token}`;
    }

    // Store challenge (24h TTL)
    const record: ChallengeRecord = {
      id: challengeId,
      domain,
      method,
      token,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      verified: false,
    };
    challengeStore.set(challengeId, record, CHALLENGE_TTL_MS);

    return c.json(
      {
        challengeId,
        challenge,
        instructions,
        expiresAt: expiresAt.toISOString(),
      },
      201,
    );
  });

  // POST /domain-verify/confirm — confirm a challenge
  domainVerify.post("/domain-verify/confirm", async (c) => {
    const rawBody = await c.req.json();
    const parsed = confirmChallengeSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const { challengeId } = parsed.data;

    // Look up challenge
    const record = challengeStore.get(challengeId);
    if (!record) {
      throw new NotFoundError("Challenge not found or has expired");
    }

    if (record.verified) {
      // Already verified — return the existing result
      return c.json({
        verified: true,
        domain: record.domain,
        method: record.method,
        verifiedAt: record.verifiedAt,
      });
    }

    // Execute verification based on method
    let result: { verified: boolean; detail?: string };

    if (record.method === "dns-txt") {
      result = await verifyDnsChallenge(record.domain, record.token, resolveTxt);
    } else {
      result = await verifyHttpChallenge(
        record.domain,
        record.token,
        httpFetch,
        resolve4,
        resolve6,
      );
    }

    if (!result.verified) {
      throw new VerificationError(result.detail ?? "Domain verification failed");
    }

    // Mark as verified
    const verifiedAt = new Date().toISOString();
    const updatedRecord: ChallengeRecord = {
      ...record,
      verified: true,
      verifiedAt,
    };
    challengeStore.set(challengeId, updatedRecord, CHALLENGE_TTL_MS);

    return c.json({
      verified: true,
      domain: record.domain,
      method: record.method,
      verifiedAt,
    });
  });

  return domainVerify;
}

// Export helpers for testing
export { isPrivateIP, generateToken, CHALLENGE_TTL_MS, DNS_SUBDOMAIN, HTTP_WELL_KNOWN_PATH };
