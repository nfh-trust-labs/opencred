import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock node:dns at the module level
const mockResolveTxt = vi.fn<(domain: string) => Promise<string[][]>>();
const mockResolve4 = vi.fn<(domain: string) => Promise<string[]>>();
const mockResolve6 = vi.fn<(domain: string) => Promise<string[]>>();
const mockResolverResolveTxt = vi.fn<
  (domain: string, cb: (err: Error | null, addresses: string[][]) => void) => void
>();
const mockSetServers = vi.fn();

vi.mock("node:dns", () => {
  return {
    default: {
      promises: {
        resolveTxt: (...args: Parameters<typeof mockResolveTxt>) => mockResolveTxt(...args),
        resolve4: (...args: Parameters<typeof mockResolve4>) => mockResolve4(...args),
        resolve6: (...args: Parameters<typeof mockResolve6>) => mockResolve6(...args),
      },
      Resolver: class MockResolver {
        setServers = mockSetServers;
        resolveTxt = mockResolverResolveTxt;
      },
    },
  };
});

import {
  generateChallenge,
  ChallengeStore,
  verifyDomainOwnership,
} from "../challenge-manager.js";

// ─── Challenge Generation ─────────────────────────────────────────────

describe("generateChallenge", () => {
  it("generates a challenge with a 64-char hex token (256-bit entropy)", () => {
    const result = generateChallenge("example.com", "dns-txt");

    expect(result.token).toMatch(/^[0-9a-f]{64}$/);
  });

  it("generates a unique challengeId in UUID format", () => {
    const result = generateChallenge("example.com", "dns-txt");

    expect(result.challengeId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it("generates unique tokens for each call", () => {
    const r1 = generateChallenge("example.com", "dns-txt");
    const r2 = generateChallenge("example.com", "dns-txt");

    expect(r1.token).not.toBe(r2.token);
    expect(r1.challengeId).not.toBe(r2.challengeId);
  });

  it("sets expiry to 24 hours from now", () => {
    const before = Date.now();
    const result = generateChallenge("example.com", "dns-txt");
    const after = Date.now();

    const expectedMin = before + 24 * 60 * 60 * 1000;
    const expectedMax = after + 24 * 60 * 60 * 1000;

    expect(result.expiresAt.getTime()).toBeGreaterThanOrEqual(expectedMin);
    expect(result.expiresAt.getTime()).toBeLessThanOrEqual(expectedMax);
  });

  it("provides DNS TXT instructions for dns-txt method", () => {
    const result = generateChallenge("example.com", "dns-txt");

    expect(result.instructions).toContain("DNS TXT record");
    expect(result.instructions).toContain("example.com");
    expect(result.instructions).toContain(`opencred-verify=${result.token}`);
  });

  it("provides HTTP URL instructions for http method", () => {
    const result = generateChallenge("example.com", "http");

    expect(result.instructions).toContain(
      `https://example.com/.well-known/opencred-challenge/${result.challengeId}`,
    );
  });

  it("returns the correct domain and method", () => {
    const result = generateChallenge("university.example", "dns-txt");

    expect(result.domain).toBe("university.example");
    expect(result.method).toBe("dns-txt");
  });

  it("rejects empty domain", () => {
    expect(() => generateChallenge("", "dns-txt")).toThrow("Domain is required");
  });

  it("rejects domain with protocol", () => {
    expect(() => generateChallenge("https://example.com", "dns-txt")).toThrow(
      "Domain must not include a protocol",
    );
  });

  it("rejects domain with path", () => {
    expect(() => generateChallenge("example.com/path", "dns-txt")).toThrow(
      "Domain must not include a path",
    );
  });

  it("rejects invalid verification method", () => {
    expect(() =>
      generateChallenge("example.com", "invalid" as "dns-txt"),
    ).toThrow("Invalid verification method");
  });

  it("rejects overly long domain name", () => {
    const longDomain = "a".repeat(254) + ".com";
    expect(() => generateChallenge(longDomain, "dns-txt")).toThrow(
      "Domain name exceeds maximum length",
    );
  });
});

// ─── Challenge Store ──────────────────────────────────────────────────

describe("ChallengeStore", () => {
  let store: ChallengeStore;

  beforeEach(() => {
    store = new ChallengeStore();
  });

  it("creates and retrieves a challenge", () => {
    const challenge = store.create("example.com", "dns-txt", "test-token");

    expect(challenge.id).toBeTruthy();
    expect(challenge.domain).toBe("example.com");
    expect(challenge.method).toBe("dns-txt");
    expect(challenge.token).toBe("test-token");
    expect(challenge.status).toBe("pending");

    const retrieved = store.get(challenge.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe(challenge.id);
  });

  it("generates unique IDs for each challenge", () => {
    const c1 = store.create("example.com", "dns-txt", "token1");
    const c2 = store.create("example.com", "dns-txt", "token2");

    expect(c1.id).not.toBe(c2.id);
  });

  it("returns undefined for non-existent challenge", () => {
    const result = store.get("non-existent-id");

    expect(result).toBeUndefined();
  });

  it("deletes a challenge", () => {
    const challenge = store.create("example.com", "dns-txt", "token");
    expect(store.get(challenge.id)).toBeDefined();

    const deleted = store.delete(challenge.id);
    expect(deleted).toBe(true);
    expect(store.get(challenge.id)).toBeUndefined();
  });

  it("returns false when deleting non-existent challenge", () => {
    const deleted = store.delete("non-existent-id");

    expect(deleted).toBe(false);
  });

  it("sets expiry to 24 hours in the future", () => {
    const before = Date.now();
    const challenge = store.create("example.com", "dns-txt", "token");
    const after = Date.now();

    const expectedMin = before + 24 * 60 * 60 * 1000;
    const expectedMax = after + 24 * 60 * 60 * 1000;

    expect(challenge.expiresAt.getTime()).toBeGreaterThanOrEqual(expectedMin);
    expect(challenge.expiresAt.getTime()).toBeLessThanOrEqual(expectedMax);
  });

  it("returns undefined for expired challenges", () => {
    const challenge = store.create("example.com", "dns-txt", "token");
    challenge.expiresAt = new Date(Date.now() - 1000);

    const result = store.get(challenge.id);
    expect(result).toBeUndefined();
  });

  it("cleans up expired challenges", () => {
    const c1 = store.create("example.com", "dns-txt", "token1");
    const c2 = store.create("example.com", "dns-txt", "token2");
    store.create("example.com", "dns-txt", "token3");

    c1.expiresAt = new Date(Date.now() - 1000);
    c2.expiresAt = new Date(Date.now() - 1000);

    const removed = store.cleanup();
    expect(removed).toBe(2);
    expect(store.size).toBe(1);
  });

  it("cleanup returns 0 when no challenges are expired", () => {
    store.create("example.com", "dns-txt", "token1");
    store.create("example.com", "dns-txt", "token2");

    const removed = store.cleanup();
    expect(removed).toBe(0);
    expect(store.size).toBe(2);
  });

  it("reports correct size", () => {
    expect(store.size).toBe(0);

    store.create("a.com", "dns-txt", "t1");
    expect(store.size).toBe(1);

    store.create("b.com", "dns-txt", "t2");
    expect(store.size).toBe(2);
  });
});

// ─── verifyDomainOwnership ────────────────────────────────────────────

describe("verifyDomainOwnership", () => {
  let store: ChallengeStore;

  beforeEach(() => {
    store = new ChallengeStore();
    mockResolveTxt.mockReset();
    mockResolverResolveTxt.mockReset();
    mockSetServers.mockReset();
    mockResolve4.mockReset();
    mockResolve6.mockReset();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns error for empty challenge ID", async () => {
    const result = await verifyDomainOwnership("", store);

    expect(result.verified).toBe(false);
    expect(result.error).toContain("Challenge ID is required");
  });

  it("returns error for non-existent challenge", async () => {
    const result = await verifyDomainOwnership("non-existent-id", store);

    expect(result.verified).toBe(false);
    expect(result.error).toContain("not found or expired");
  });

  it("returns error for expired challenge", async () => {
    const challenge = store.create("example.com", "dns-txt", "token");
    challenge.expiresAt = new Date(Date.now() - 1000);

    const result = await verifyDomainOwnership(challenge.id, store);

    expect(result.verified).toBe(false);
    expect(result.error).toContain("not found or expired");
  });

  it("returns error for already-verified challenge", async () => {
    const challenge = store.create("example.com", "dns-txt", "token");
    challenge.status = "verified";

    const result = await verifyDomainOwnership(challenge.id, store);

    expect(result.verified).toBe(false);
    expect(result.error).toContain("already been verified");
    expect(result.domain).toBe("example.com");
  });

  it("verifies a DNS TXT challenge successfully", async () => {
    const challenge = store.create("example.com", "dns-txt", "my-token");

    mockResolveTxt.mockResolvedValue([["opencred-verify=my-token"]]);
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, [["opencred-verify=my-token"]]);
    });

    const result = await verifyDomainOwnership(challenge.id, store);

    expect(result.verified).toBe(true);
    expect(result.domain).toBe("example.com");
    expect(result.method).toBe("dns-txt");
    expect(result.verifiedAt).toBeDefined();
    expect(store.get(challenge.id)?.status).toBe("verified");
  });

  it("verifies an HTTP challenge successfully", async () => {
    const challenge = store.create("example.com", "http", "http-token");

    mockResolve4.mockResolvedValue(["93.184.216.34"]);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("http-token", { status: 200 }),
    );

    const result = await verifyDomainOwnership(challenge.id, store);

    expect(result.verified).toBe(true);
    expect(result.domain).toBe("example.com");
    expect(result.method).toBe("http");
    expect(result.verifiedAt).toBeDefined();
  });

  it("returns failure when DNS verification fails", async () => {
    const challenge = store.create("example.com", "dns-txt", "my-token");

    mockResolveTxt.mockResolvedValue([]);
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, []);
    });

    const result = await verifyDomainOwnership(challenge.id, store);

    expect(result.verified).toBe(false);
    expect(result.error).toContain("expected record or response not found");
    expect(store.get(challenge.id)?.status).toBe("failed");
  });

  it("sets status to failed on verification error", async () => {
    const challenge = store.create("evil.example", "http", "token");

    mockResolve4.mockResolvedValue(["10.0.0.1"]);

    const result = await verifyDomainOwnership(challenge.id, store);

    expect(result.verified).toBe(false);
    expect(result.domain).toBe("evil.example");
    expect(result.error).toContain("private or loopback IP");
    expect(store.get(challenge.id)?.status).toBe("failed");
  });

  it("end-to-end: generate -> store -> verify flow", async () => {
    // Step 1: Generate challenge
    const details = generateChallenge("university.example", "dns-txt");

    // Step 2: Store the challenge
    const challenge = store.create(
      details.domain,
      details.method,
      details.token,
    );

    // Step 3: Simulate the domain owner adding the TXT record
    mockResolveTxt.mockResolvedValue([
      [`opencred-verify=${details.token}`],
    ]);
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, [[`opencred-verify=${details.token}`]]);
    });

    // Step 4: Verify
    const result = await verifyDomainOwnership(challenge.id, store);

    expect(result.verified).toBe(true);
    expect(result.domain).toBe("university.example");
    expect(result.method).toBe("dns-txt");
    expect(result.verifiedAt).toBeDefined();
    expect(new Date(result.verifiedAt!).getTime()).not.toBeNaN();
  });

  it("end-to-end: generate -> store -> verify HTTP flow", async () => {
    const details = generateChallenge("issuer.example", "http");

    const challenge = store.create(
      details.domain,
      details.method,
      details.token,
    );

    mockResolve4.mockResolvedValue(["203.0.113.1"]);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(details.token, { status: 200 }),
    );

    const result = await verifyDomainOwnership(challenge.id, store);

    expect(result.verified).toBe(true);
    expect(result.domain).toBe("issuer.example");
    expect(result.method).toBe("http");
  });
});
