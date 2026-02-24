import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import { jwtVerify } from "jose";
import { TTLStore } from "@opencred/state";
import {
  createDomainVerificationRoutes,
  createTypeBOnboardingRoutes,
  type ChallengeRecord,
  type DomainVerificationDeps,
  type TypeBOnboardingDeps,
  type SslSubject,
  type SslSubjectExtractor,
  CHALLENGE_TTL_MS,
  DNS_SUBDOMAIN,
  typeBSlugify,
  buildDomainNamespace,
  buildIssuerName,
} from "../routes/domain-verification.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

// --- Mock registerDelegation ---
vi.mock("@opencred/delegation", async () => {
  const actual =
    await vi.importActual<typeof import("@opencred/delegation")>("@opencred/delegation");
  return {
    ...actual,
    registerDelegation: vi.fn().mockResolvedValue({
      id: "urn:uuid:mock-delegation-id",
      issuerDid: "did:example:delegator",
      delegateDid: "did:key:z6Mk-opencred",
      scope: [],
      validFrom: new Date().toISOString(),
      validUntil: new Date(Date.now() + 3600_000).toISOString(),
      certificate: {},
    }),
  };
});

import { registerDelegation } from "@opencred/delegation";

const mockedRegister = vi.mocked(registerDelegation);
const logger = makeTestLogger();

// --- Test constants ---

const TEST_TOKEN_SECRET = "test-capability-token-key-must-be-at-least-32-chars";
const TEST_TOKEN_ISSUER = "opencred-test";
const TEST_TOKEN_EXPIRY = 3600;
const TEST_TOKEN_KEY = new TextEncoder().encode(TEST_TOKEN_SECRET);
const TEST_OPENCRED_DID = "did:key:z6MktestedOpencredKey123456";

// --- Response types ---

interface TypeBResponseBody {
  namespace: string;
  capabilityToken: string;
  issuerIdentifier: string;
  expiresAt: string;
  sslSubject: SslSubject;
  delegationId?: string;
}

interface InitiateResponse {
  challengeId: string;
  challenge: string;
  instructions: string;
  expiresAt: string;
}

interface ErrorBody {
  error: { code: string; message: string };
}

// --- Mock factories ---

function createMockSslExtractor(subject: SslSubject = {}): SslSubjectExtractor {
  return async (_domain: string) => subject;
}

function createFailingSslExtractor(): SslSubjectExtractor {
  return async (_domain: string) => {
    throw new Error("TLS connection refused");
  };
}

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

interface TestAppOptions {
  sslSubject?: SslSubject;
  extractSslSubject?: SslSubjectExtractor;
  opencredSigningKeyDid?: string;
  dediClient?: TypeBOnboardingDeps["dediClient"];
  domainVerificationOverrides?: Partial<DomainVerificationDeps>;
}

function createTestApp(options: TestAppOptions = {}) {
  const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);

  const sslExtractor =
    options.extractSslSubject ??
    createMockSslExtractor(
      options.sslSubject ?? {
        CN: "example.com",
        O: "Example Inc",
        OU: "Engineering",
        C: "US",
      },
    );

  const domainVerificationDeps: DomainVerificationDeps = {
    challengeStore: store,
    dnsResolveTxt: createMockDnsResolveTxt(),
    httpFetch: createMockHttpFetch(),
    dnsResolve4: createMockResolve4(),
    dnsResolve6: createMockResolve6(),
    extractSslSubject: sslExtractor,
    ...options.domainVerificationOverrides,
  };

  const typeBDeps: TypeBOnboardingDeps = {
    ...domainVerificationDeps,
    capabilityTokenKey: TEST_TOKEN_KEY,
    tokenIssuer: TEST_TOKEN_ISSUER,
    tokenExpirySeconds: TEST_TOKEN_EXPIRY,
    opencredSigningKeyDid: options.opencredSigningKeyDid,
    dediClient: options.dediClient,
  };

  const app = new Hono();
  app.route("/onboarding", createDomainVerificationRoutes(domainVerificationDeps));
  app.route("/onboarding", createTypeBOnboardingRoutes(typeBDeps));
  app.onError(errorHandler(logger));

  return { app, store };
}

// --- Helper: initiate + verify a challenge, return the verified challengeId ---

async function initiateAndVerifyChallenge(
  app: Hono,
  store: TTLStore<ChallengeRecord>,
  domain = "example.com",
): Promise<string> {
  // Initiate
  const initRes = await app.request("/onboarding/domain-verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, method: "dns-txt" }),
  });
  expect(initRes.status).toBe(201);
  const initData = (await initRes.json()) as InitiateResponse;

  // Mark as verified directly in the store (simulates successful domain-verify/confirm)
  const record = store.get(initData.challengeId);
  expect(record).toBeDefined();
  const verifiedRecord: ChallengeRecord = {
    ...record!,
    verified: true,
    verifiedAt: new Date().toISOString(),
  };
  store.set(initData.challengeId, verifiedRecord, CHALLENGE_TTL_MS);

  return initData.challengeId;
}

// ========================================
// Unit tests: helpers
// ========================================

describe("buildDomainNamespace", () => {
  it("builds namespace from all SSL subject fields", () => {
    const ns = buildDomainNamespace("example.com", {
      CN: "example.com",
      O: "Example Inc",
      C: "US",
    });
    expect(ns).toBe("urn:opencred:issuer:domain:us:example-inc:example-com");
  });

  it("builds namespace with partial SSL subject fields", () => {
    const ns = buildDomainNamespace("example.com", { O: "Example Inc" });
    expect(ns).toBe("urn:opencred:issuer:domain:example-inc");
  });

  it("falls back to domain when no SSL subject fields", () => {
    const ns = buildDomainNamespace("example.com", {});
    expect(ns).toBe("urn:opencred:issuer:domain:example-com");
  });

  it("handles special characters in SSL subject fields", () => {
    const ns = buildDomainNamespace("example.com", {
      CN: "*.example.com",
      O: "Example & Co. Ltd.",
      C: "GB",
    });
    expect(ns).toBe("urn:opencred:issuer:domain:gb:example-co-ltd:example-com");
  });
});

describe("buildIssuerName", () => {
  it("prefers O field", () => {
    expect(buildIssuerName("example.com", { O: "Example Inc", CN: "example.com" })).toBe(
      "Example Inc",
    );
  });

  it("falls back to CN", () => {
    expect(buildIssuerName("example.com", { CN: "example.com" })).toBe("example.com");
  });

  it("falls back to domain", () => {
    expect(buildIssuerName("example.com", {})).toBe("example.com");
  });
});

describe("typeBSlugify", () => {
  it("lowercases and replaces non-alphanumeric chars", () => {
    expect(typeBSlugify("Example Inc.")).toBe("example-inc");
  });

  it("strips leading/trailing hyphens", () => {
    expect(typeBSlugify("--Hello World--")).toBe("hello-world");
  });

  it("collapses multiple special chars", () => {
    expect(typeBSlugify("A & B & C")).toBe("a-b-c");
  });
});

// ========================================
// SSL subject extraction (mock tests)
// ========================================

describe("SSL subject extraction", () => {
  it("returns all fields when present", async () => {
    const extractor = createMockSslExtractor({
      CN: "example.com",
      O: "Example Inc",
      OU: "IT Dept",
      C: "US",
    });
    const result = await extractor("example.com");
    expect(result.CN).toBe("example.com");
    expect(result.O).toBe("Example Inc");
    expect(result.OU).toBe("IT Dept");
    expect(result.C).toBe("US");
  });

  it("returns partial fields when some are missing", async () => {
    const extractor = createMockSslExtractor({ CN: "example.com" });
    const result = await extractor("example.com");
    expect(result.CN).toBe("example.com");
    expect(result.O).toBeUndefined();
    expect(result.OU).toBeUndefined();
    expect(result.C).toBeUndefined();
  });

  it("returns empty subject when no fields are present", async () => {
    const extractor = createMockSslExtractor({});
    const result = await extractor("example.com");
    expect(result.CN).toBeUndefined();
    expect(result.O).toBeUndefined();
  });

  it("rejects when TLS connection fails", async () => {
    const extractor = createFailingSslExtractor();
    await expect(extractor("example.com")).rejects.toThrow("TLS connection refused");
  });
});

// ========================================
// POST /onboarding/type-b
// ========================================

describe("POST /onboarding/type-b", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("input validation", () => {
    it("returns 400 for empty body", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/type-b", {
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
      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ signingPreference: "delegated" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for invalid signingPreference", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: "ch_test", signingPreference: "local" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });
  });

  describe("challenge validation", () => {
    it("returns 404 for non-existent challengeId", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: "ch_nonexistent0000000000000000000" }),
      });
      expect(res.status).toBe(404);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("NOT_FOUND");
    });

    it("returns 400 when domain has not been verified yet", async () => {
      const { app } = createTestApp();

      // Initiate but do NOT confirm
      const initRes = await app.request("/onboarding/domain-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
      });
      const initData = (await initRes.json()) as InitiateResponse;

      // Try type-b without confirming
      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VERIFICATION_ERROR");
      expect(body.error.message).toContain("not been verified");
    });
  });

  describe("SSL extraction errors", () => {
    it("returns 400 when SSL extraction fails", async () => {
      const { app, store } = createTestApp({
        extractSslSubject: createFailingSslExtractor(),
      });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VERIFICATION_ERROR");
      expect(body.error.message).toContain("Failed to extract SSL certificate");
    });
  });

  describe("successful Type B onboarding (interface signing)", () => {
    it("returns 201 with namespace, token, and SSL subject", async () => {
      const sslSubject: SslSubject = {
        CN: "example.com",
        O: "Example Inc",
        OU: "Engineering",
        C: "US",
      };
      const { app, store } = createTestApp({ sslSubject });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId, signingPreference: "interface" }),
      });

      expect(res.status).toBe(201);
      const body = (await res.json()) as TypeBResponseBody;

      expect(body.namespace).toBe("urn:opencred:issuer:domain:us:example-inc:example-com");
      expect(body.capabilityToken).toBeDefined();
      expect(body.issuerIdentifier).toBe("domain:example-com");
      expect(body.expiresAt).toBeDefined();
      expect(new Date(body.expiresAt).getTime()).toBeGreaterThan(Date.now());

      // SSL subject should be present in the response
      expect(body.sslSubject).toEqual(sslSubject);

      // No delegationId for interface signing
      expect(body.delegationId).toBeUndefined();
    });

    it("issues a valid capability token with interface scopes", async () => {
      const { app, store } = createTestApp();

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId, signingPreference: "interface" }),
      });

      expect(res.status).toBe(201);
      const body = (await res.json()) as TypeBResponseBody;

      // Verify the JWT
      const { payload } = await jwtVerify(body.capabilityToken, TEST_TOKEN_KEY, {
        issuer: TEST_TOKEN_ISSUER,
      });

      expect(payload.sub).toBe("domain:example-com");
      expect(payload.iss).toBe(TEST_TOKEN_ISSUER);
      expect(payload.scope).toEqual(["credentials:build", "credentials:revoke"]);
      expect(payload.namespace).toBe(body.namespace);
    });
  });

  describe("successful Type B onboarding (delegated signing)", () => {
    it("returns 201 with delegationId when using delegated signing", async () => {
      const sslSubject: SslSubject = {
        CN: "secure.example.com",
        O: "Secure Corp",
        C: "DE",
      };
      const { app, store } = createTestApp({
        sslSubject,
        opencredSigningKeyDid: TEST_OPENCRED_DID,
      });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId }), // defaults to "delegated"
      });

      expect(res.status).toBe(201);
      const body = (await res.json()) as TypeBResponseBody;

      expect(body.namespace).toBe("urn:opencred:issuer:domain:de:secure-corp:secure-example-com");
      expect(body.capabilityToken).toBeDefined();
      expect(body.issuerIdentifier).toBe("domain:example-com");
      expect(body.delegationId).toBeDefined();
      expect(body.delegationId).toMatch(/^urn:uuid:/);
      expect(body.sslSubject).toEqual(sslSubject);
    });

    it("issues a valid capability token with delegated scopes", async () => {
      const { app, store } = createTestApp({
        opencredSigningKeyDid: TEST_OPENCRED_DID,
      });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId, signingPreference: "delegated" }),
      });

      expect(res.status).toBe(201);
      const body = (await res.json()) as TypeBResponseBody;

      const { payload } = await jwtVerify(body.capabilityToken, TEST_TOKEN_KEY, {
        issuer: TEST_TOKEN_ISSUER,
      });

      expect(payload.scope).toEqual(["credentials:issue-delegated", "credentials:revoke"]);
    });

    it("returns error when delegated signing requested but no OpenCred key configured", async () => {
      const { app, store } = createTestApp({
        opencredSigningKeyDid: undefined,
      });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId, signingPreference: "delegated" }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
      expect(body.error.message).toContain("no OpenCred signing key configured");
    });

    it("registers delegation in DeDi when client is provided", async () => {
      const mockDediClient = {
        post: vi.fn().mockResolvedValue({ id: "mock-id" }),
        get: vi.fn(),
        patch: vi.fn(),
        delete: vi.fn(),
        healthCheck: vi.fn(),
      };

      const { app, store } = createTestApp({
        opencredSigningKeyDid: TEST_OPENCRED_DID,
        dediClient: mockDediClient as unknown as TypeBOnboardingDeps["dediClient"],
      });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId, signingPreference: "delegated" }),
      });

      expect(res.status).toBe(201);

      // registerDelegation should have been called
      expect(mockedRegister).toHaveBeenCalledTimes(1);
      const callArgs = mockedRegister.mock.calls[0];
      expect(callArgs[1].certificate).toBeDefined();
      expect(callArgs[1].certificate.delegator.id).toBe("https://example.com");
      expect(callArgs[1].certificate.delegator.name).toBe("Example Inc");
      expect(callArgs[1].certificate.delegatee.id).toBe(TEST_OPENCRED_DID);
      expect(callArgs[1].certificate.proof?.type).toBe("DomainVerificationAuthorisation");
    });
  });

  describe("signing preference defaults", () => {
    it("defaults to delegated signing when signingPreference is not provided", async () => {
      const { app, store } = createTestApp({
        opencredSigningKeyDid: TEST_OPENCRED_DID,
      });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId }),
      });

      expect(res.status).toBe(201);
      const body = (await res.json()) as TypeBResponseBody;

      // Delegated signing is default — should have delegationId
      expect(body.delegationId).toBeDefined();

      // Verify scopes match delegated
      const { payload } = await jwtVerify(body.capabilityToken, TEST_TOKEN_KEY, {
        issuer: TEST_TOKEN_ISSUER,
      });
      expect(payload.scope).toEqual(["credentials:issue-delegated", "credentials:revoke"]);
    });
  });

  describe("SSL subject variations", () => {
    it("handles domain with only CN in SSL subject", async () => {
      const { app, store } = createTestApp({
        sslSubject: { CN: "example.com" },
      });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId, signingPreference: "interface" }),
      });

      expect(res.status).toBe(201);
      const body = (await res.json()) as TypeBResponseBody;
      expect(body.namespace).toBe("urn:opencred:issuer:domain:example-com");
      expect(body.sslSubject).toEqual({ CN: "example.com" });
    });

    it("handles domain with empty SSL subject (falls back to domain)", async () => {
      const { app, store } = createTestApp({
        sslSubject: {},
      });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId, signingPreference: "interface" }),
      });

      expect(res.status).toBe(201);
      const body = (await res.json()) as TypeBResponseBody;
      expect(body.namespace).toBe("urn:opencred:issuer:domain:example-com");
    });

    it("handles wildcard CN certificates", async () => {
      const { app, store } = createTestApp({
        sslSubject: { CN: "*.example.com", O: "Example Inc", C: "US" },
      });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId, signingPreference: "interface" }),
      });

      expect(res.status).toBe(201);
      const body = (await res.json()) as TypeBResponseBody;
      expect(body.namespace).toBe("urn:opencred:issuer:domain:us:example-inc:example-com");
    });
  });

  describe("full end-to-end Type B flow", () => {
    it("initiate challenge -> confirm -> type-b onboarding", async () => {
      const store = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 0);
      const sslSubject: SslSubject = {
        CN: "example.com",
        O: "Example Inc",
        C: "US",
      };

      // Create DNS mock that will verify the challenge
      // We need to build the app, initiate, get the token, then rebuild with
      // proper DNS records and proper SSL extractor

      // Step 1: Build app for initiation
      const dnsRecordsHolder: Record<string, string[][]> = {};
      const domainVerificationDeps: DomainVerificationDeps = {
        challengeStore: store,
        dnsResolveTxt: async (hostname: string, _resolverIp: string) => {
          const result = dnsRecordsHolder[hostname];
          if (result) return result;
          const err = new Error(`queryTxt ENOTFOUND ${hostname}`);
          (err as NodeJS.ErrnoException).code = "ENOTFOUND";
          throw err;
        },
        httpFetch: createMockHttpFetch(),
        dnsResolve4: createMockResolve4(),
        dnsResolve6: createMockResolve6(),
        extractSslSubject: createMockSslExtractor(sslSubject),
      };

      const typeBDeps: TypeBOnboardingDeps = {
        ...domainVerificationDeps,
        capabilityTokenKey: TEST_TOKEN_KEY,
        tokenIssuer: TEST_TOKEN_ISSUER,
        tokenExpirySeconds: TEST_TOKEN_EXPIRY,
        opencredSigningKeyDid: TEST_OPENCRED_DID,
      };

      const app = new Hono();
      app.route("/onboarding", createDomainVerificationRoutes(domainVerificationDeps));
      app.route("/onboarding", createTypeBOnboardingRoutes(typeBDeps));
      app.onError(errorHandler(logger));

      // Step 2: Initiate challenge
      const initRes = await app.request("/onboarding/domain-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
      });
      expect(initRes.status).toBe(201);
      const initData = (await initRes.json()) as InitiateResponse;

      // Step 3: Set up DNS records with the token
      const token = initData.challenge.replace("opencred-verify=", "");
      dnsRecordsHolder[`${DNS_SUBDOMAIN}.example.com`] = [[`opencred-verify=${token}`]];

      // Step 4: Confirm the challenge
      const confirmRes = await app.request("/onboarding/domain-verify/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: initData.challengeId }),
      });
      expect(confirmRes.status).toBe(200);
      const confirmBody = (await confirmRes.json()) as { verified: boolean };
      expect(confirmBody.verified).toBe(true);

      // Step 5: Complete Type B onboarding
      const typeBRes = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challengeId: initData.challengeId,
          signingPreference: "delegated",
        }),
      });
      expect(typeBRes.status).toBe(201);
      const typeBBody = (await typeBRes.json()) as TypeBResponseBody;

      // Verify the full response
      expect(typeBBody.namespace).toBe("urn:opencred:issuer:domain:us:example-inc:example-com");
      expect(typeBBody.capabilityToken).toBeDefined();
      expect(typeBBody.issuerIdentifier).toBe("domain:example-com");
      expect(typeBBody.expiresAt).toBeDefined();
      expect(typeBBody.sslSubject).toEqual(sslSubject);
      expect(typeBBody.delegationId).toBeDefined();
      expect(typeBBody.delegationId).toMatch(/^urn:uuid:/);

      // Verify the JWT token
      const { payload } = await jwtVerify(typeBBody.capabilityToken, TEST_TOKEN_KEY, {
        issuer: TEST_TOKEN_ISSUER,
      });
      expect(payload.sub).toBe("domain:example-com");
      expect(payload.scope).toEqual(["credentials:issue-delegated", "credentials:revoke"]);
      expect(payload.namespace).toBe(typeBBody.namespace);
    });
  });

  describe("error responses do not leak secrets", () => {
    it("does not include internal paths or stack traces in error responses", async () => {
      const { app } = createTestApp();
      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: "" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      const bodyStr = JSON.stringify(body);
      expect(bodyStr).not.toContain("/Users/");
      expect(bodyStr).not.toContain("node_modules");
      expect(bodyStr).not.toContain("stack");
    });

    it("does not leak SSL connection details on extraction failure", async () => {
      const { app, store } = createTestApp({
        extractSslSubject: createFailingSslExtractor(),
      });

      const challengeId = await initiateAndVerifyChallenge(app, store);

      const res = await app.request("/onboarding/type-b", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      const bodyStr = JSON.stringify(body);
      // Should NOT contain internal error message
      expect(bodyStr).not.toContain("TLS connection refused");
      // Should contain our sanitized message
      expect(body.error.message).toContain("Failed to extract SSL certificate");
    });
  });
});
