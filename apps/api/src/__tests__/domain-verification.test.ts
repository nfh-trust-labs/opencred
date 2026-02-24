import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { TTLStore } from "@opencred/state";
import {
  createDomainVerificationRoutes,
  isPrivateIP,
  generateToken,
  CHALLENGE_TTL_MS,
  DNS_SUBDOMAIN,
  HTTP_WELL_KNOWN_PATH,
  type ChallengeRecord,
  type DomainVerificationDeps,
} from "../routes/domain-verification.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

const logger = makeTestLogger();

// --- Response types ---

interface InitiateResponse {
  challengeId: string;
  challenge: string;
  instructions: string;
  expiresAt: string;
}

interface ConfirmResponse {
  verified: boolean;
  domain: string;
  method: string;
  verifiedAt?: string;
}

interface ErrorBody {
  error: { code: string; message: string };
}

// --- Mock factories ---

function createMockDnsResolveTxt(
  records: Record<string, string[][]> = {},
): (hostname: string, _resolverIp: string) => Promise<string[][]> {
  return async (hostname: string, _resolverIp: string) => {
    const result = records[hostname];
    if (result) return result;
    const err = new Error(`queryTxt ENOTFOUND ${hostname}`);
    (err as NodeJS.ErrnoException).code = "ENOTFOUND";
    throw err;
  };
}

function createMockHttpFetch(
  responses: Record<string, { ok: boolean; body: string }> = {},
): (url: string) => Promise<{ ok: boolean; text: () => Promise<string> }> {
  return async (url: string) => {
    const response = responses[url];
    if (response) {
      return {
        ok: response.ok,
        text: async () => response.body,
      };
    }
    throw new Error(`fetch failed: ${url}`);
  };
}

function createMockResolve4(
  records: Record<string, string[]> = {},
): (hostname: string) => Promise<string[]> {
  return async (hostname: string) => {
    const result = records[hostname];
    if (result) return result;
    throw new Error(`resolve4 ENOTFOUND ${hostname}`);
  };
}

function createMockResolve6(
  records: Record<string, string[]> = {},
): (hostname: string) => Promise<string[]> {
  return async (hostname: string) => {
    const result = records[hostname];
    if (result) return result;
    throw new Error(`resolve6 ENOTFOUND ${hostname}`);
  };
}

// --- Test app factory ---

function createTestApp(overrides: Partial<DomainVerificationDeps> = {}) {
  const store = overrides.challengeStore ?? new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
  const app = new Hono();
  app.route(
    "/onboarding",
    createDomainVerificationRoutes({
      challengeStore: store,
      dnsResolveTxt: overrides.dnsResolveTxt ?? createMockDnsResolveTxt(),
      httpFetch: overrides.httpFetch ?? createMockHttpFetch(),
      dnsResolve4: overrides.dnsResolve4 ?? createMockResolve4(),
      dnsResolve6: overrides.dnsResolve6 ?? createMockResolve6(),
    }),
  );
  app.onError(errorHandler(logger));
  return { app, store };
}

// --- Helper to initiate and return the challenge ---

async function initiateChallenge(
  app: Hono,
  body: Record<string, unknown>,
): Promise<{ res: Response; data: InitiateResponse }> {
  const res = await app.request("/onboarding/domain-verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = (await res.json()) as InitiateResponse;
  return { res, data };
}

// ==========================================
// POST /onboarding/domain-verify — Initiate
// ==========================================

describe("POST /onboarding/domain-verify", () => {
  describe("input validation", () => {
    it("returns 400 for empty body", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/domain-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for missing domain", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/domain-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ method: "dns-txt" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for missing method", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/domain-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "example.com" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for invalid method", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/domain-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "example.com", method: "ftp-challenge" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for invalid domain format", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/domain-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "not a domain!", method: "dns-txt" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for IP address as domain", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/domain-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "192.168.1.1", method: "dns-txt" }),
      });
      expect(res.status).toBe(400);
    });
  });

  describe("DNS TXT challenge initiation", () => {
    it("returns 201 with challenge details for dns-txt method", async () => {
      const { app } = createTestApp();
      const { res, data } = await initiateChallenge(app, {
        domain: "example.com",
        method: "dns-txt",
      });

      expect(res.status).toBe(201);
      expect(data.challengeId).toBeDefined();
      expect(data.challengeId).toMatch(/^ch_[0-9a-f]{32}$/);
      expect(data.challenge).toMatch(/^opencred-verify=[0-9a-f]{64}$/);
      expect(data.instructions).toContain(DNS_SUBDOMAIN);
      expect(data.instructions).toContain("example.com");
      expect(data.expiresAt).toBeDefined();
      expect(new Date(data.expiresAt).getTime()).toBeGreaterThan(Date.now());
    });

    it("challenge token has 256-bit entropy (64 hex chars)", async () => {
      const { app } = createTestApp();
      const { data } = await initiateChallenge(app, {
        domain: "example.com",
        method: "dns-txt",
      });

      // Extract token from "opencred-verify=<token>"
      const token = data.challenge.replace("opencred-verify=", "");
      expect(token).toMatch(/^[0-9a-f]{64}$/);
      // 64 hex chars = 32 bytes = 256 bits
      expect(Buffer.from(token, "hex").length).toBe(32);
    });

    it("generates unique challenge IDs for each request", async () => {
      const { app } = createTestApp();
      const { data: data1 } = await initiateChallenge(app, {
        domain: "example.com",
        method: "dns-txt",
      });
      const { data: data2 } = await initiateChallenge(app, {
        domain: "example.com",
        method: "dns-txt",
      });

      expect(data1.challengeId).not.toBe(data2.challengeId);
      expect(data1.challenge).not.toBe(data2.challenge);
    });

    it("expires in 24 hours", async () => {
      const { app } = createTestApp();
      const { data } = await initiateChallenge(app, {
        domain: "example.com",
        method: "dns-txt",
      });

      const expiresAt = new Date(data.expiresAt).getTime();
      const now = Date.now();
      // Should be approximately 24h from now (within 5 seconds tolerance)
      expect(expiresAt - now).toBeGreaterThan(CHALLENGE_TTL_MS - 5000);
      expect(expiresAt - now).toBeLessThan(CHALLENGE_TTL_MS + 5000);
    });
  });

  describe("HTTP challenge initiation", () => {
    it("returns 201 with challenge details for http-challenge method", async () => {
      const { app } = createTestApp();
      const { res, data } = await initiateChallenge(app, {
        domain: "example.com",
        method: "http-challenge",
      });

      expect(res.status).toBe(201);
      expect(data.challengeId).toBeDefined();
      expect(data.challenge).toMatch(/^[0-9a-f]{64}$/);
      expect(data.instructions).toContain(HTTP_WELL_KNOWN_PATH);
      expect(data.instructions).toContain("example.com");
      expect(data.expiresAt).toBeDefined();
    });

    it("instructions contain the correct well-known URL", async () => {
      const { app } = createTestApp();
      const { data } = await initiateChallenge(app, {
        domain: "test.example.org",
        method: "http-challenge",
      });

      const expectedUrl = `https://test.example.org/${HTTP_WELL_KNOWN_PATH}/${data.challenge}`;
      expect(data.instructions).toContain(expectedUrl);
    });
  });
});

// ================================================
// POST /onboarding/domain-verify/confirm — Confirm
// ================================================

describe("POST /onboarding/domain-verify/confirm", () => {
  describe("input validation", () => {
    it("returns 400 for empty body", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for missing challengeId", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ somethingElse: "value" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });
  });

  describe("challenge not found", () => {
    it("returns 404 for non-existent challengeId", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: "ch_nonexistent0000000000000000000" }),
      });
      expect(res.status).toBe(404);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("NOT_FOUND");
      expect(body.error.message).toContain("expired");
    });
  });

  describe("expired challenge", () => {
    it("returns 404 for an expired challenge", async () => {
      // Insert a challenge record with a very short TTL directly into the store
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const challengeId = "ch_expired00000000000000000000000";
      const record: ChallengeRecord = {
        id: challengeId,
        domain: "example.com",
        method: "dns-txt",
        token: "a".repeat(64),
        createdAt: new Date(Date.now() - 100_000).toISOString(),
        expiresAt: new Date(Date.now() - 50_000).toISOString(),
        verified: false,
      };
      // Store with 1ms TTL so it expires immediately
      store.set(challengeId, record, 1);

      // Wait for the entry to expire in the TTL store
      await new Promise((resolve) => setTimeout(resolve, 10));

      const { app } = createTestApp({ challengeStore: store });

      // Try to confirm — should be expired (TTL store returns undefined)
      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId }),
      });
      expect(res.status).toBe(404);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("NOT_FOUND");
    });
  });

  describe("DNS TXT verification", () => {
    it("returns verified=true when DNS TXT record is found by multiple resolvers", async () => {
      // First initiate a challenge to get the token
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const { app: initApp } = createTestApp({ challengeStore: store });
      const { data: initData } = await initiateChallenge(initApp, {
        domain: "example.com",
        method: "dns-txt",
      });

      // Extract the token from the challenge
      const token = initData.challenge.replace("opencred-verify=", "");

      // Create a new app with mock DNS that returns the correct TXT record
      const dnsRecords: Record<string, string[][]> = {
        [`${DNS_SUBDOMAIN}.example.com`]: [[`opencred-verify=${token}`]],
      };
      const app = new Hono();
      app.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(dnsRecords),
          httpFetch: createMockHttpFetch(),
          dnsResolve4: createMockResolve4(),
          dnsResolve6: createMockResolve6(),
        }),
      );
      app.onError(errorHandler(logger));

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as ConfirmResponse;
      expect(body.verified).toBe(true);
      expect(body.domain).toBe("example.com");
      expect(body.method).toBe("dns-txt");
      expect(body.verifiedAt).toBeDefined();
    });

    it("returns error when DNS TXT record is not found", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      // DNS mock returns no records (default mock throws ENOTFOUND)
      const { app } = createTestApp({
        challengeStore: store,
        dnsResolveTxt: createMockDnsResolveTxt({}),
      });

      // Initiate challenge
      const { data: initData } = await initiateChallenge(app, {
        domain: "example.com",
        method: "dns-txt",
      });

      // Confirm — should fail because no TXT records found
      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VERIFICATION_ERROR");
    });

    it("returns error when DNS TXT record has wrong token value", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const dnsRecords: Record<string, string[][]> = {
        [`${DNS_SUBDOMAIN}.example.com`]: [["opencred-verify=wrongtoken"]],
      };
      const { app } = createTestApp({
        challengeStore: store,
        dnsResolveTxt: createMockDnsResolveTxt(dnsRecords),
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "example.com",
        method: "dns-txt",
      });

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VERIFICATION_ERROR");
    });

    it("uses multiple DNS resolvers for cache poisoning mitigation", async () => {
      const resolverIPs: string[] = [];
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);

      // Create a DNS resolver that tracks which resolver IPs were used
      const trackingResolver = async (hostname: string, resolverIp: string) => {
        resolverIPs.push(resolverIp);
        // Return empty — we just want to verify multiple resolvers are queried
        const err = new Error(`queryTxt ENOTFOUND ${hostname}`);
        (err as NodeJS.ErrnoException).code = "ENOTFOUND";
        throw err;
      };

      const { app } = createTestApp({
        challengeStore: store,
        dnsResolveTxt: trackingResolver,
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "example.com",
        method: "dns-txt",
      });

      await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      // Should have queried at least 3 resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9)
      expect(resolverIPs.length).toBeGreaterThanOrEqual(3);
      expect(resolverIPs).toContain("8.8.8.8");
      expect(resolverIPs).toContain("1.1.1.1");
      expect(resolverIPs).toContain("9.9.9.9");
    });
  });

  describe("HTTP challenge verification", () => {
    it("returns verified=true when HTTP challenge file is served correctly", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);

      // We need to first initiate to get the token, then set up the mock
      const tempApp = new Hono();
      tempApp.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(),
          httpFetch: createMockHttpFetch(),
          dnsResolve4: createMockResolve4({ "example.com": ["93.184.216.34"] }),
          dnsResolve6: createMockResolve6(),
        }),
      );
      tempApp.onError(errorHandler(logger));

      const { data: initData } = await initiateChallenge(tempApp, {
        domain: "example.com",
        method: "http-challenge",
      });

      const token = initData.challenge;
      const challengeUrl = `https://example.com/${HTTP_WELL_KNOWN_PATH}/${token}`;

      // Create app with the correct mock responses
      const app = new Hono();
      app.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(),
          httpFetch: createMockHttpFetch({
            [challengeUrl]: { ok: true, body: token },
          }),
          dnsResolve4: createMockResolve4({ "example.com": ["93.184.216.34"] }),
          dnsResolve6: createMockResolve6(),
        }),
      );
      app.onError(errorHandler(logger));

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as ConfirmResponse;
      expect(body.verified).toBe(true);
      expect(body.domain).toBe("example.com");
      expect(body.method).toBe("http-challenge");
      expect(body.verifiedAt).toBeDefined();
    });

    it("returns error when HTTP challenge file returns wrong content", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);

      const tempApp = new Hono();
      tempApp.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(),
          httpFetch: createMockHttpFetch(),
          dnsResolve4: createMockResolve4({ "example.com": ["93.184.216.34"] }),
          dnsResolve6: createMockResolve6(),
        }),
      );
      tempApp.onError(errorHandler(logger));

      const { data: initData } = await initiateChallenge(tempApp, {
        domain: "example.com",
        method: "http-challenge",
      });

      const token = initData.challenge;
      const challengeUrl = `https://example.com/${HTTP_WELL_KNOWN_PATH}/${token}`;

      const app = new Hono();
      app.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(),
          httpFetch: createMockHttpFetch({
            [challengeUrl]: { ok: true, body: "wrong-content" },
          }),
          dnsResolve4: createMockResolve4({ "example.com": ["93.184.216.34"] }),
          dnsResolve6: createMockResolve6(),
        }),
      );
      app.onError(errorHandler(logger));

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VERIFICATION_ERROR");
    });

    it("returns error when HTTP endpoint returns non-200", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);

      const tempApp = new Hono();
      tempApp.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(),
          httpFetch: createMockHttpFetch(),
          dnsResolve4: createMockResolve4({ "example.com": ["93.184.216.34"] }),
          dnsResolve6: createMockResolve6(),
        }),
      );
      tempApp.onError(errorHandler(logger));

      const { data: initData } = await initiateChallenge(tempApp, {
        domain: "example.com",
        method: "http-challenge",
      });

      const token = initData.challenge;
      const challengeUrl = `https://example.com/${HTTP_WELL_KNOWN_PATH}/${token}`;

      const app = new Hono();
      app.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(),
          httpFetch: createMockHttpFetch({
            [challengeUrl]: { ok: false, body: "Not Found" },
          }),
          dnsResolve4: createMockResolve4({ "example.com": ["93.184.216.34"] }),
          dnsResolve6: createMockResolve6(),
        }),
      );
      app.onError(errorHandler(logger));

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VERIFICATION_ERROR");
    });

    it("returns error when domain does not resolve", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);

      // No DNS records at all
      const { app } = createTestApp({
        challengeStore: store,
        dnsResolve4: createMockResolve4({}),
        dnsResolve6: createMockResolve6({}),
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "example.com",
        method: "http-challenge",
      });

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VERIFICATION_ERROR");
      expect(body.error.message).toContain("does not resolve");
    });
  });

  describe("SSRF prevention", () => {
    it("rejects domain resolving to 10.x.x.x (private)", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const { app } = createTestApp({
        challengeStore: store,
        dnsResolve4: createMockResolve4({ "evil.example.com": ["10.0.0.1"] }),
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "evil.example.com",
        method: "http-challenge",
      });

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VERIFICATION_ERROR");
      expect(body.error.message).toContain("private");
    });

    it("rejects domain resolving to 172.16.x.x (private)", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const { app } = createTestApp({
        challengeStore: store,
        dnsResolve4: createMockResolve4({ "evil.example.com": ["172.16.0.1"] }),
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "evil.example.com",
        method: "http-challenge",
      });

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.message).toContain("private");
    });

    it("rejects domain resolving to 192.168.x.x (private)", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const { app } = createTestApp({
        challengeStore: store,
        dnsResolve4: createMockResolve4({ "evil.example.com": ["192.168.1.100"] }),
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "evil.example.com",
        method: "http-challenge",
      });

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.message).toContain("private");
    });

    it("rejects domain resolving to 127.0.0.1 (loopback)", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const { app } = createTestApp({
        challengeStore: store,
        dnsResolve4: createMockResolve4({ "evil.example.com": ["127.0.0.1"] }),
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "evil.example.com",
        method: "http-challenge",
      });

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.message).toContain("private");
    });

    it("rejects domain resolving to ::1 (IPv6 loopback)", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const { app } = createTestApp({
        challengeStore: store,
        dnsResolve4: createMockResolve4({}),
        dnsResolve6: createMockResolve6({ "evil.example.com": ["::1"] }),
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "evil.example.com",
        method: "http-challenge",
      });

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.message).toContain("private");
    });

    it("rejects domain resolving to 169.254.x.x (link-local)", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const { app } = createTestApp({
        challengeStore: store,
        dnsResolve4: createMockResolve4({ "evil.example.com": ["169.254.169.254"] }),
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "evil.example.com",
        method: "http-challenge",
      });

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.message).toContain("private");
    });

    it("allows domain resolving to a public IP", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);

      // First initiate on a temp app
      const tempApp = new Hono();
      tempApp.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(),
          httpFetch: createMockHttpFetch(),
          dnsResolve4: createMockResolve4({ "example.com": ["93.184.216.34"] }),
          dnsResolve6: createMockResolve6(),
        }),
      );
      tempApp.onError(errorHandler(logger));

      const { data: initData } = await initiateChallenge(tempApp, {
        domain: "example.com",
        method: "http-challenge",
      });

      const token = initData.challenge;
      const challengeUrl = `https://example.com/${HTTP_WELL_KNOWN_PATH}/${token}`;

      // Now confirm with mock that serves the correct token
      const app = new Hono();
      app.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(),
          httpFetch: createMockHttpFetch({
            [challengeUrl]: { ok: true, body: token },
          }),
          dnsResolve4: createMockResolve4({ "example.com": ["93.184.216.34"] }),
          dnsResolve6: createMockResolve6(),
        }),
      );
      app.onError(errorHandler(logger));

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as ConfirmResponse;
      expect(body.verified).toBe(true);
    });

    it("rejects when any resolved IP is private even if others are public", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const { app } = createTestApp({
        challengeStore: store,
        // One public, one private
        dnsResolve4: createMockResolve4({
          "mixed.example.com": ["93.184.216.34", "10.0.0.1"],
        }),
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "mixed.example.com",
        method: "http-challenge",
      });

      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.message).toContain("private");
    });
  });

  describe("already verified challenge", () => {
    it("returns the existing verification result for an already-verified challenge", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);

      const tempApp = new Hono();
      tempApp.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(),
          httpFetch: createMockHttpFetch(),
          dnsResolve4: createMockResolve4({ "example.com": ["93.184.216.34"] }),
          dnsResolve6: createMockResolve6(),
        }),
      );
      tempApp.onError(errorHandler(logger));

      const { data: initData } = await initiateChallenge(tempApp, {
        domain: "example.com",
        method: "http-challenge",
      });

      const token = initData.challenge;
      const challengeUrl = `https://example.com/${HTTP_WELL_KNOWN_PATH}/${token}`;

      const app = new Hono();
      app.route(
        "/onboarding",
        createDomainVerificationRoutes({
          challengeStore: store,
          dnsResolveTxt: createMockDnsResolveTxt(),
          httpFetch: createMockHttpFetch({
            [challengeUrl]: { ok: true, body: token },
          }),
          dnsResolve4: createMockResolve4({ "example.com": ["93.184.216.34"] }),
          dnsResolve6: createMockResolve6(),
        }),
      );
      app.onError(errorHandler(logger));

      // First confirm
      const res1 = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });
      expect(res1.status).toBe(200);
      const body1 = (await res1.json()) as ConfirmResponse;
      expect(body1.verified).toBe(true);

      // Second confirm — should still succeed without re-verifying
      const res2 = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });
      expect(res2.status).toBe(200);
      const body2 = (await res2.json()) as ConfirmResponse;
      expect(body2.verified).toBe(true);
      expect(body2.verifiedAt).toBe(body1.verifiedAt);
    });
  });

  describe("error responses do not leak secrets", () => {
    it("does not include internal paths or stack traces in error responses", async () => {
      const { app } = createTestApp();

      // Invalid input
      const res = await app.request("/onboarding/domain-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "invalid!", method: "bad" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      const bodyStr = JSON.stringify(body);
      expect(bodyStr).not.toContain("/Users/");
      expect(bodyStr).not.toContain("node_modules");
      expect(bodyStr).not.toContain("stack");
    });

    it("does not leak challenge tokens in error messages", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const { app } = createTestApp({
        challengeStore: store,
        dnsResolveTxt: createMockDnsResolveTxt({}),
      });

      const { data: initData } = await initiateChallenge(app, {
        domain: "example.com",
        method: "dns-txt",
      });

      const token = initData.challenge.replace("opencred-verify=", "");

      // Attempt confirmation (will fail because no DNS records)
      const res = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      const bodyStr = JSON.stringify(body);
      // The token should NOT appear in error responses
      expect(bodyStr).not.toContain(token);
    });
  });
});

// ========================================
// isPrivateIP unit tests
// ========================================

describe("isPrivateIP", () => {
  describe("IPv4 private ranges", () => {
    it("rejects 10.x.x.x", () => {
      expect(isPrivateIP("10.0.0.0")).toBe(true);
      expect(isPrivateIP("10.255.255.255")).toBe(true);
      expect(isPrivateIP("10.0.0.1")).toBe(true);
    });

    it("rejects 172.16-31.x.x", () => {
      expect(isPrivateIP("172.16.0.0")).toBe(true);
      expect(isPrivateIP("172.31.255.255")).toBe(true);
      expect(isPrivateIP("172.20.1.1")).toBe(true);
    });

    it("allows 172.32.x.x", () => {
      expect(isPrivateIP("172.32.0.0")).toBe(false);
    });

    it("rejects 192.168.x.x", () => {
      expect(isPrivateIP("192.168.0.0")).toBe(true);
      expect(isPrivateIP("192.168.255.255")).toBe(true);
      expect(isPrivateIP("192.168.1.1")).toBe(true);
    });

    it("rejects 127.x.x.x (loopback)", () => {
      expect(isPrivateIP("127.0.0.1")).toBe(true);
      expect(isPrivateIP("127.255.255.255")).toBe(true);
    });

    it("rejects 0.x.x.x", () => {
      expect(isPrivateIP("0.0.0.0")).toBe(true);
    });

    it("rejects 169.254.x.x (link-local)", () => {
      expect(isPrivateIP("169.254.0.0")).toBe(true);
      expect(isPrivateIP("169.254.169.254")).toBe(true);
    });

    it("rejects 100.64-127.x.x (CGNAT)", () => {
      expect(isPrivateIP("100.64.0.0")).toBe(true);
      expect(isPrivateIP("100.127.255.255")).toBe(true);
    });

    it("allows 100.63.x.x", () => {
      expect(isPrivateIP("100.63.255.255")).toBe(false);
    });

    it("rejects multicast (224-239.x.x.x)", () => {
      expect(isPrivateIP("224.0.0.1")).toBe(true);
      expect(isPrivateIP("239.255.255.255")).toBe(true);
    });

    it("rejects reserved (240+.x.x.x)", () => {
      expect(isPrivateIP("240.0.0.0")).toBe(true);
      expect(isPrivateIP("255.255.255.255")).toBe(true);
    });
  });

  describe("IPv4 public ranges", () => {
    it("allows well-known public IPs", () => {
      expect(isPrivateIP("8.8.8.8")).toBe(false);
      expect(isPrivateIP("1.1.1.1")).toBe(false);
      expect(isPrivateIP("93.184.216.34")).toBe(false);
      expect(isPrivateIP("185.199.108.153")).toBe(false);
    });
  });

  describe("IPv6 addresses", () => {
    it("rejects ::1 (loopback)", () => {
      expect(isPrivateIP("::1")).toBe(true);
    });

    it("rejects :: (unspecified)", () => {
      expect(isPrivateIP("::")).toBe(true);
    });

    it("rejects fe80:: (link-local)", () => {
      expect(isPrivateIP("fe80::1")).toBe(true);
      expect(isPrivateIP("fe80::")).toBe(true);
    });

    it("rejects fc00::/fd00:: (unique local)", () => {
      expect(isPrivateIP("fc00::1")).toBe(true);
      expect(isPrivateIP("fd00::1")).toBe(true);
    });

    it("allows public IPv6 addresses", () => {
      expect(isPrivateIP("2001:db8::1")).toBe(false);
      expect(isPrivateIP("2606:4700:4700::1111")).toBe(false);
    });
  });

  describe("malformed addresses", () => {
    it("treats malformed IPv4 as private", () => {
      expect(isPrivateIP("999.999.999.999")).toBe(true);
      expect(isPrivateIP("not-an-ip")).toBe(false); // not IPv4 format, goes to IPv6 path
    });
  });
});

// ========================================
// generateToken unit test
// ========================================

describe("generateToken", () => {
  it("generates a 64-character hex string (256-bit entropy)", () => {
    const token = generateToken();
    expect(token).toMatch(/^[0-9a-f]{64}$/);
    expect(Buffer.from(token, "hex").length).toBe(32);
  });

  it("generates unique tokens each time", () => {
    const tokens = new Set<string>();
    for (let i = 0; i < 100; i++) {
      tokens.add(generateToken());
    }
    expect(tokens.size).toBe(100);
  });
});
