import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock node:dns at the module level before any imports that use it
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
  DomainChallengeStore,
  verifyDnsTxtChallenge,
  verifyHttpChallenge,
  verifyDomainOwnership,
  isPrivateIP,
} from "../domain-verification.js";

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

  it("provides HTTP URL instructions for http-challenge method", () => {
    const result = generateChallenge("example.com", "http-challenge");

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

describe("DomainChallengeStore", () => {
  let store: DomainChallengeStore;

  beforeEach(() => {
    store = new DomainChallengeStore();
  });

  it("creates and retrieves a challenge", () => {
    const challenge = store.create("example.com", "dns-txt", "test-token");

    expect(challenge.id).toBeTruthy();
    expect(challenge.domain).toBe("example.com");
    expect(challenge.method).toBe("dns-txt");
    expect(challenge.token).toBe("test-token");
    expect(challenge.verified).toBe(false);

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
    // Manually set expiry to the past
    challenge.expiresAt = new Date(Date.now() - 1000);

    const result = store.get(challenge.id);
    expect(result).toBeUndefined();
  });

  it("cleans up expired challenges", () => {
    const c1 = store.create("example.com", "dns-txt", "token1");
    const c2 = store.create("example.com", "dns-txt", "token2");
    store.create("example.com", "dns-txt", "token3"); // not expired

    // Expire two challenges
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

// ─── DNS TXT Verification ─────────────────────────────────────────────

describe("verifyDnsTxtChallenge", () => {
  beforeEach(() => {
    mockResolveTxt.mockReset();
    mockResolverResolveTxt.mockReset();
    mockSetServers.mockReset();
  });

  it("returns true when TXT record matches on both resolvers", async () => {
    mockResolveTxt.mockResolvedValue([["opencred-verify=abc123"]]);
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, [["opencred-verify=abc123"]]);
    });

    const result = await verifyDnsTxtChallenge("example.com", "abc123");

    expect(result).toBe(true);
    expect(mockSetServers).toHaveBeenCalledWith(["8.8.8.8"]);
  });

  it("returns false when TXT record does not match", async () => {
    mockResolveTxt.mockResolvedValue([["opencred-verify=wrong-token"]]);
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, [["opencred-verify=wrong-token"]]);
    });

    const result = await verifyDnsTxtChallenge("example.com", "abc123");

    expect(result).toBe(false);
  });

  it("handles multiple TXT records and finds the match", async () => {
    const records = [
      ["v=spf1 include:_spf.example.com ~all"],
      ["opencred-verify=abc123"],
      ["google-site-verification=xyz"],
    ];
    mockResolveTxt.mockResolvedValue(records);
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, records);
    });

    const result = await verifyDnsTxtChallenge("example.com", "abc123");

    expect(result).toBe(true);
  });

  it("handles chunked TXT records", async () => {
    // DNS TXT records can be returned in chunks
    mockResolveTxt.mockResolvedValue([["opencred-verify=", "abc123"]]);
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, [["opencred-verify=", "abc123"]]);
    });

    const result = await verifyDnsTxtChallenge("example.com", "abc123");

    expect(result).toBe(true);
  });

  it("returns false when DNS lookup fails", async () => {
    mockResolveTxt.mockRejectedValue(new Error("ENOTFOUND"));
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(new Error("ENOTFOUND"), []);
    });

    const result = await verifyDnsTxtChallenge("nonexistent.example", "abc123");

    expect(result).toBe(false);
  });

  it("returns false when default resolver matches but secondary does not", async () => {
    // Default says yes
    mockResolveTxt.mockResolvedValue([["opencred-verify=abc123"]]);
    // Secondary says no (possible cache poisoning)
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, [["opencred-verify=different-token"]]);
    });

    const result = await verifyDnsTxtChallenge("example.com", "abc123");

    expect(result).toBe(false);
  });

  it("returns false when no TXT records exist", async () => {
    mockResolveTxt.mockResolvedValue([]);
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, []);
    });

    const result = await verifyDnsTxtChallenge("example.com", "abc123");

    expect(result).toBe(false);
  });

  it("throws on empty domain", async () => {
    await expect(verifyDnsTxtChallenge("", "abc123")).rejects.toThrow(
      "Domain is required",
    );
  });

  it("throws on empty token", async () => {
    await expect(verifyDnsTxtChallenge("example.com", "")).rejects.toThrow(
      "Expected token is required",
    );
  });
});

// ─── HTTP Challenge Verification ──────────────────────────────────────

describe("verifyHttpChallenge", () => {
  beforeEach(() => {
    mockResolve4.mockReset();
    mockResolve6.mockReset();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns true when response body matches expected token", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34"]);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("test-token-123", { status: 200 }),
    );

    const result = await verifyHttpChallenge(
      "example.com",
      "challenge-id-1",
      "test-token-123",
    );

    expect(result).toBe(true);
  });

  it("returns false when response body does not match", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34"]);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("wrong-token", { status: 200 }),
    );

    const result = await verifyHttpChallenge(
      "example.com",
      "challenge-id-1",
      "test-token-123",
    );

    expect(result).toBe(false);
  });

  it("returns false when HTTP status is not ok", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34"]);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("Not Found", { status: 404 }),
    );

    const result = await verifyHttpChallenge(
      "example.com",
      "challenge-id-1",
      "test-token-123",
    );

    expect(result).toBe(false);
  });

  it("returns false when fetch throws (e.g., timeout)", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34"]);

    vi.spyOn(globalThis, "fetch").mockRejectedValue(
      new Error("AbortError: The operation was aborted"),
    );

    const result = await verifyHttpChallenge(
      "example.com",
      "challenge-id-1",
      "test-token-123",
    );

    expect(result).toBe(false);
  });

  it("trims whitespace from response body", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34"]);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("  test-token-123  \n", { status: 200 }),
    );

    const result = await verifyHttpChallenge(
      "example.com",
      "challenge-id-1",
      "test-token-123",
    );

    expect(result).toBe(true);
  });

  it("fetches the correct well-known URL", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34"]);

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("token", { status: 200 }),
    );

    await verifyHttpChallenge("example.com", "my-challenge-id", "token");

    expect(fetchSpy).toHaveBeenCalledWith(
      "https://example.com/.well-known/opencred-challenge/my-challenge-id",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("throws on empty domain", async () => {
    await expect(
      verifyHttpChallenge("", "id", "token"),
    ).rejects.toThrow("Domain is required");
  });

  it("throws on empty challenge ID", async () => {
    await expect(
      verifyHttpChallenge("example.com", "", "token"),
    ).rejects.toThrow("Challenge ID is required");
  });

  it("throws on empty token", async () => {
    await expect(
      verifyHttpChallenge("example.com", "id", ""),
    ).rejects.toThrow("Expected token is required");
  });

  // SSRF prevention tests
  describe("SSRF prevention", () => {
    it("rejects domain resolving to 127.0.0.1 (loopback)", async () => {
      mockResolve4.mockResolvedValue(["127.0.0.1"]);

      await expect(
        verifyHttpChallenge("evil.example", "id", "token"),
      ).rejects.toThrow("private or loopback IP");
    });

    it("rejects domain resolving to 10.x.x.x (private)", async () => {
      mockResolve4.mockResolvedValue(["10.0.0.1"]);

      await expect(
        verifyHttpChallenge("evil.example", "id", "token"),
      ).rejects.toThrow("private or loopback IP");
    });

    it("rejects domain resolving to 172.16.x.x (private)", async () => {
      mockResolve4.mockResolvedValue(["172.16.0.1"]);

      await expect(
        verifyHttpChallenge("evil.example", "id", "token"),
      ).rejects.toThrow("private or loopback IP");
    });

    it("rejects domain resolving to 192.168.x.x (private)", async () => {
      mockResolve4.mockResolvedValue(["192.168.1.1"]);

      await expect(
        verifyHttpChallenge("evil.example", "id", "token"),
      ).rejects.toThrow("private or loopback IP");
    });

    it("rejects domain resolving to IPv6 loopback (::1)", async () => {
      mockResolve4.mockRejectedValue(new Error("ENODATA"));
      mockResolve6.mockResolvedValue(["::1"]);

      await expect(
        verifyHttpChallenge("evil.example", "id", "token"),
      ).rejects.toThrow("private or loopback IP");
    });

    it("rejects domain resolving to IPv6 unique-local (fc00::/7)", async () => {
      mockResolve4.mockRejectedValue(new Error("ENODATA"));
      mockResolve6.mockResolvedValue(["fd00::1"]);

      await expect(
        verifyHttpChallenge("evil.example", "id", "token"),
      ).rejects.toThrow("private or loopback IP");
    });

    it("allows domain resolving to public IP", async () => {
      mockResolve4.mockResolvedValue(["8.8.8.8"]);

      vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response("token", { status: 200 }),
      );

      const result = await verifyHttpChallenge("example.com", "id", "token");
      expect(result).toBe(true);
    });

    it("throws when DNS resolution fails entirely", async () => {
      mockResolve4.mockRejectedValue(new Error("ENOTFOUND"));
      mockResolve6.mockRejectedValue(new Error("ENOTFOUND"));

      await expect(
        verifyHttpChallenge("nonexistent.example", "id", "token"),
      ).rejects.toThrow("Failed to resolve domain");
    });
  });
});

// ─── isPrivateIP ──────────────────────────────────────────────────────

describe("isPrivateIP", () => {
  it("identifies 10.x.x.x as private", () => {
    expect(isPrivateIP("10.0.0.1")).toBe(true);
    expect(isPrivateIP("10.255.255.255")).toBe(true);
  });

  it("identifies 172.16-31.x.x as private", () => {
    expect(isPrivateIP("172.16.0.1")).toBe(true);
    expect(isPrivateIP("172.31.255.255")).toBe(true);
  });

  it("does not flag 172.15 or 172.32 as private", () => {
    expect(isPrivateIP("172.15.0.1")).toBe(false);
    expect(isPrivateIP("172.32.0.1")).toBe(false);
  });

  it("identifies 192.168.x.x as private", () => {
    expect(isPrivateIP("192.168.0.1")).toBe(true);
    expect(isPrivateIP("192.168.255.255")).toBe(true);
  });

  it("identifies 127.x.x.x as loopback", () => {
    expect(isPrivateIP("127.0.0.1")).toBe(true);
    expect(isPrivateIP("127.255.255.255")).toBe(true);
  });

  it("identifies ::1 as IPv6 loopback", () => {
    expect(isPrivateIP("::1")).toBe(true);
  });

  it("identifies fc00::/fd00:: as unique-local", () => {
    expect(isPrivateIP("fc00::1")).toBe(true);
    expect(isPrivateIP("fd00::1")).toBe(true);
  });

  it("identifies fe80:: as link-local", () => {
    expect(isPrivateIP("fe80::1")).toBe(true);
  });

  it("does not flag public IPs", () => {
    expect(isPrivateIP("8.8.8.8")).toBe(false);
    expect(isPrivateIP("1.1.1.1")).toBe(false);
    expect(isPrivateIP("93.184.216.34")).toBe(false);
    expect(isPrivateIP("2001:db8::1")).toBe(false);
  });

  it("returns false for non-IP strings", () => {
    expect(isPrivateIP("not-an-ip")).toBe(false);
  });

  it("identifies 169.254.x.x as link-local", () => {
    expect(isPrivateIP("169.254.0.1")).toBe(true);
  });

  it("identifies 0.x.x.x as reserved", () => {
    expect(isPrivateIP("0.0.0.0")).toBe(true);
  });
});

// ─── High-Level: verifyDomainOwnership ────────────────────────────────

describe("verifyDomainOwnership", () => {
  let store: DomainChallengeStore;

  beforeEach(() => {
    store = new DomainChallengeStore();
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
    challenge.verified = true;

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
    // Verify the challenge is marked as verified in the store
    expect(store.get(challenge.id)?.verified).toBe(true);
  });

  it("verifies an HTTP challenge successfully", async () => {
    const challenge = store.create("example.com", "http-challenge", "http-token");

    mockResolve4.mockResolvedValue(["93.184.216.34"]);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("http-token", { status: 200 }),
    );

    const result = await verifyDomainOwnership(challenge.id, store);

    expect(result.verified).toBe(true);
    expect(result.domain).toBe("example.com");
    expect(result.method).toBe("http-challenge");
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
    // Challenge should NOT be marked as verified
    expect(store.get(challenge.id)?.verified).toBe(false);
  });

  it("handles verification errors gracefully", async () => {
    const challenge = store.create("evil.example", "http-challenge", "token");

    mockResolve4.mockResolvedValue(["10.0.0.1"]);

    const result = await verifyDomainOwnership(challenge.id, store);

    expect(result.verified).toBe(false);
    expect(result.domain).toBe("evil.example");
    expect(result.error).toContain("private or loopback IP");
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
});
