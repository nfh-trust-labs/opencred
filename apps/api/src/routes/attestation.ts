/**
 * Attestation challenge and verification routes.
 *
 * These endpoints implement the "Quick Start" (Workflow 3) attestation flow:
 * 1. POST /attestation/challenge — issuer provides domain + public key info,
 *    receives a DNS TXT or HTTP challenge to prove domain ownership.
 * 2. POST /attestation/challenge/:id/verify — verifies the challenge and
 *    issues a signed Key Attestation VC.
 *
 * The attestation VC is signed by OpenCred's own key, endorsing the
 * issuer's public key after domain verification.
 */

import { Hono } from "hono";
import { z } from "zod";
import { randomBytes } from "node:crypto";
import { promises as dns } from "node:dns";
import { ValidationError, VerificationError, NotFoundError } from "@opencred/shared";
import { createKeyAttestationVC } from "@opencred/key-attestation";
import type { PublicKeyJwk } from "@opencred/key-attestation";
import { TTLStore } from "@opencred/state";
import type { SigningKeyProvider } from "@opencred/crypto";
import type { UnsignedCredential } from "@opencred/vc-core";

// --- Constants ---

const CHALLENGE_TTL_MS = 24 * 60 * 60 * 1000;
const TOKEN_BYTES = 32;
const DNS_TXT_PREFIX = "opencred-verify=";
const DNS_SUBDOMAIN = "_opencred-verify";
const HTTP_WELL_KNOWN_PATH = ".well-known/opencred-challenge";

const DNS_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"];
const DNS_MIN_AGREEMENT = 2;

// --- Types ---

export interface AttestationChallengeRecord {
  id: string;
  domain: string;
  method: "dns-txt" | "http-challenge";
  token: string;
  createdAt: string;
  expiresAt: string;
  verified: boolean;
  verifiedAt?: string;
  // Issuer info stored at challenge creation
  publicKeyJwk: PublicKeyJwk;
  organizationName: string;
  issuerDid: string;
  verificationMethodId: string;
  keyFingerprint: string;
  keyAlgorithm: string;
  // Cached attestation (set after first successful verification)
  attestationCredential?: Record<string, unknown>;
}

export interface AttestationRouteDeps {
  challengeStore?: TTLStore<AttestationChallengeRecord>;
  dnsResolveTxt?: (hostname: string, resolverIp: string) => Promise<string[][]>;
  httpFetch?: (url: string) => Promise<{ ok: boolean; text: () => Promise<string> }>;
  dnsResolve4?: (hostname: string) => Promise<string[]>;
  dnsResolve6?: (hostname: string) => Promise<string[]>;
  signingKeyProvider?: SigningKeyProvider;
  opencredDid?: string;
  logger?: { warn(msg: string): void };
  prepareProof?: typeof import("@opencred/crypto").prepareProof;
  completeProof?: typeof import("@opencred/crypto").completeProof;
}

// --- SSRF prevention ---

function isPrivateIP(ip: string): boolean {
  if (ip.includes(".")) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return true;
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a >= 224) return true;
    return false;
  }
  const normalized = ip.toLowerCase().replace(/^\[|]$/g, "");
  if (normalized === "::1" || normalized === "::") return true;
  if (normalized.startsWith("fe80") || normalized.startsWith("fc") || normalized.startsWith("fd"))
    return true;
  if (normalized.startsWith("::ffff:")) {
    const ipv4Part = normalized.slice(7);
    if (ipv4Part.includes(".")) return isPrivateIP(ipv4Part);
  }
  return false;
}

// --- Zod schemas ---

const domainRegex = /^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/;

const challengeSchema = z.object({
  domain: z
    .string()
    .min(1, "domain is required")
    .refine((d) => domainRegex.test(d), "domain must be a valid domain name"),
  method: z.enum(["dns-txt", "http-challenge"], {
    errorMap: () => ({ message: "method must be 'dns-txt' or 'http-challenge'" }),
  }),
  publicKeyJwk: z
    .object({ kty: z.string() })
    .passthrough()
    .refine((jwk) => jwk.kty.length > 0, "publicKeyJwk.kty is required"),
  organizationName: z.string().min(1, "organizationName is required"),
  issuerDid: z
    .string()
    .min(1, "issuerDid is required")
    .refine((d) => d.startsWith("did:"), "issuerDid must be a valid DID"),
  verificationMethodId: z.string().min(1, "verificationMethodId is required"),
  keyFingerprint: z.string().min(1, "keyFingerprint is required"),
  keyAlgorithm: z.string().min(1, "keyAlgorithm is required"),
});

// --- Default implementations ---

async function defaultDnsResolveTxt(hostname: string, resolverIp: string): Promise<string[][]> {
  const resolver = new dns.Resolver();
  resolver.setServers([resolverIp]);
  return resolver.resolveTxt(hostname);
}

async function defaultDnsResolve4(hostname: string): Promise<string[]> {
  return dns.resolve4(hostname);
}

async function defaultDnsResolve6(hostname: string): Promise<string[]> {
  try {
    return await dns.resolve6(hostname);
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENODATA" || code === "ENOTFOUND") return [];
    throw err;
  }
}

async function defaultHttpFetch(
  url: string,
): Promise<{ ok: boolean; text: () => Promise<string> }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    return await fetch(url, { signal: controller.signal, redirect: "error" });
  } finally {
    clearTimeout(timeout);
  }
}

// --- Helpers ---

function generateToken(): string {
  return randomBytes(TOKEN_BYTES).toString("hex");
}

function generateChallengeId(): string {
  return `ch_${randomBytes(16).toString("hex")}`;
}

async function verifyDnsChallenge(
  domain: string,
  token: string,
  resolveTxt: (hostname: string, resolverIp: string) => Promise<string[][]>,
  logger?: { warn(msg: string): void },
): Promise<{ verified: boolean; detail?: string }> {
  const lookupHost = `${DNS_SUBDOMAIN}.${domain}`;
  const expectedValue = `${DNS_TXT_PREFIX}${token}`;

  let matchCount = 0;
  let queryCount = 0;

  for (const resolverIp of DNS_RESOLVERS) {
    try {
      const records = await resolveTxt(lookupHost, resolverIp);
      queryCount++;
      const flatRecords = records.map((chunks) => chunks.join(""));
      if (flatRecords.includes(expectedValue)) matchCount++;
    } catch (err) {
      const detail = err instanceof Error ? err.message : "unknown error";
      logger?.warn(`DNS resolver ${resolverIp} failed for ${lookupHost}: ${detail}`);
    }
  }

  if (queryCount === 0) return { verified: false, detail: "All DNS resolvers failed" };
  if (matchCount >= DNS_MIN_AGREEMENT) return { verified: true };
  return {
    verified: false,
    detail: `DNS TXT record not found (${matchCount}/${queryCount} resolvers matched, need ${DNS_MIN_AGREEMENT})`,
  };
}

async function verifyHttpChallenge(
  domain: string,
  token: string,
  httpFetch: (url: string) => Promise<{ ok: boolean; text: () => Promise<string> }>,
  resolve4: (hostname: string) => Promise<string[]>,
  resolve6: (hostname: string) => Promise<string[]>,
  logger?: { warn(msg: string): void },
): Promise<{ verified: boolean; detail?: string }> {
  let ipv4Addrs: string[] = [];
  let ipv6Addrs: string[] = [];
  let v4Failed = false;
  let v6Failed = false;

  try {
    ipv4Addrs = await resolve4(domain);
  } catch (err) {
    v4Failed = true;
    logger?.warn(`DNS A resolution failed for ${domain}: ${err instanceof Error ? err.message : "unknown"}`);
  }

  try {
    ipv6Addrs = await resolve6(domain);
  } catch (err) {
    v6Failed = true;
    logger?.warn(`DNS AAAA resolution failed for ${domain}: ${err instanceof Error ? err.message : "unknown"}`);
  }

  if (v4Failed && v6Failed) return { verified: false, detail: "DNS resolution failed for domain" };

  const allAddrs = [...ipv4Addrs, ...ipv6Addrs];
  if (allAddrs.length === 0) return { verified: false, detail: "Domain does not resolve to any IP" };

  for (const ip of allAddrs) {
    if (isPrivateIP(ip))
      return { verified: false, detail: "Domain resolves to a private or reserved IP address" };
  }

  const url = `https://${domain}/${HTTP_WELL_KNOWN_PATH}/${token}`;
  try {
    const response = await httpFetch(url);
    if (!response.ok) return { verified: false, detail: "HTTP challenge endpoint returned non-200" };
    const body = await response.text();
    if (body.trim() === token) return { verified: true };
    return { verified: false, detail: "HTTP challenge response does not contain expected token" };
  } catch {
    return { verified: false, detail: "Failed to fetch HTTP challenge URL" };
  }
}

// --- Route factory ---

export function createAttestationRoutes(deps: AttestationRouteDeps = {}) {
  const challengeStore =
    deps.challengeStore ?? new TTLStore<AttestationChallengeRecord>(CHALLENGE_TTL_MS, 60_000);
  const resolveTxt = deps.dnsResolveTxt ?? defaultDnsResolveTxt;
  const httpFetch = deps.httpFetch ?? defaultHttpFetch;
  const resolve4 = deps.dnsResolve4 ?? defaultDnsResolve4;
  const resolve6 = deps.dnsResolve6 ?? defaultDnsResolve6;

  const app = new Hono();

  // POST /challenge — start domain verification for attestation
  app.post("/challenge", async (c) => {
    const rawBody = await c.req.json();
    const parsed = challengeSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const { domain, method, publicKeyJwk, organizationName, issuerDid, verificationMethodId, keyFingerprint, keyAlgorithm } = parsed.data;

    const token = generateToken();
    const challengeId = generateChallengeId();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + CHALLENGE_TTL_MS);

    let challenge: string;
    let instructions: string;

    if (method === "dns-txt") {
      challenge = `${DNS_TXT_PREFIX}${token}`;
      instructions =
        `Add a DNS TXT record to ${DNS_SUBDOMAIN}.${domain} with the value: ${challenge}`;
    } else {
      challenge = token;
      instructions =
        `Place a file at https://${domain}/${HTTP_WELL_KNOWN_PATH}/${token} containing exactly: ${token}`;
    }

    const record: AttestationChallengeRecord = {
      id: challengeId,
      domain,
      method,
      token,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      verified: false,
      publicKeyJwk: publicKeyJwk as PublicKeyJwk,
      organizationName,
      issuerDid,
      verificationMethodId,
      keyFingerprint,
      keyAlgorithm,
    };
    challengeStore.set(challengeId, record, CHALLENGE_TTL_MS);

    return c.json({ challengeId, challenge, instructions, expiresAt: expiresAt.toISOString() }, 201);
  });

  // POST /challenge/:id/verify — verify challenge and issue attestation VC
  app.post("/challenge/:id/verify", async (c) => {
    const challengeId = c.req.param("id");
    const record = challengeStore.get(challengeId);
    if (!record) {
      throw new NotFoundError("Challenge not found or has expired");
    }

    // Return cached attestation if already verified
    if (record.verified && record.attestationCredential) {
      return c.json({
        verified: true,
        attestationCredential: record.attestationCredential,
      });
    }

    // Verify domain ownership
    let result: { verified: boolean; detail?: string };
    if (record.method === "dns-txt") {
      result = await verifyDnsChallenge(record.domain, record.token, resolveTxt, deps.logger);
    } else {
      result = await verifyHttpChallenge(
        record.domain, record.token, httpFetch, resolve4, resolve6, deps.logger,
      );
    }

    if (!result.verified) {
      throw new VerificationError(result.detail ?? "Domain verification failed");
    }

    // Build Key Attestation VC
    if (!deps.signingKeyProvider || !deps.opencredDid) {
      return c.json(
        { error: { code: "NOT_CONFIGURED", message: "Attestation signing not configured" } },
        501,
      );
    }

    const unsignedAttestation = createKeyAttestationVC({
      opencredDid: deps.opencredDid,
      issuerDid: record.issuerDid,
      issuerKeyJwk: record.publicKeyJwk,
      keyFingerprint: record.keyFingerprint,
      keyAlgorithm: record.keyAlgorithm,
      verificationMethodId: record.verificationMethodId,
      identityVerification: {
        method: record.method,
        verifiedDomain: record.domain,
        verifiedAt: new Date().toISOString(),
        challengeId: record.id,
      },
      organizationName: record.organizationName,
    });

    // Sign the attestation VC with OpenCred's key
    const { prepareProof: defaultPrepare, completeProof: defaultComplete } = await import("@opencred/crypto");
    const doPrepare = deps.prepareProof ?? defaultPrepare;
    const doComplete = deps.completeProof ?? defaultComplete;
    const signingKey = deps.signingKeyProvider.getActiveKey();

    const unsignedVC = unsignedAttestation as unknown as UnsignedCredential;
    const { dataToSign, proofConfig } = await doPrepare(unsignedVC, {
      verificationMethod: deps.opencredDid,
      proofPurpose: "assertionMethod",
    });

    const { sign } = await import("node:crypto");
    const signature = sign("sha256", Buffer.from(dataToSign), signingKey.privateKey);
    const signedAttestation = doComplete(unsignedVC, proofConfig, new Uint8Array(signature));

    // Cache the result
    const updatedRecord: AttestationChallengeRecord = {
      ...record,
      verified: true,
      verifiedAt: new Date().toISOString(),
      attestationCredential: signedAttestation as unknown as Record<string, unknown>,
    };
    challengeStore.set(challengeId, updatedRecord, CHALLENGE_TTL_MS);

    return c.json({
      verified: true,
      attestationCredential: signedAttestation,
    });
  });

  // 405 for non-POST methods
  app.all("/challenge", (c) =>
    c.json({ error: { code: "METHOD_NOT_ALLOWED", message: "Use POST" } }, 405),
  );
  app.all("/challenge/:id/verify", (c) =>
    c.json({ error: { code: "METHOD_NOT_ALLOWED", message: "Use POST" } }, 405),
  );

  return app;
}

// Export for testing
export { isPrivateIP, DNS_SUBDOMAIN, HTTP_WELL_KNOWN_PATH, CHALLENGE_TTL_MS };
