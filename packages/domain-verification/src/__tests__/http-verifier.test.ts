import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock node:dns at the module level
const mockResolve4 = vi.fn<(domain: string) => Promise<string[]>>();
const mockResolve6 = vi.fn<(domain: string) => Promise<string[]>>();

vi.mock("node:dns", () => {
  return {
    default: {
      promises: {
        resolve4: (...args: Parameters<typeof mockResolve4>) => mockResolve4(...args),
        resolve6: (...args: Parameters<typeof mockResolve6>) => mockResolve6(...args),
      },
    },
  };
});

import { verifyHttpChallenge } from "../http-verifier.js";

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
      expect.objectContaining({ method: "GET", redirect: "error" }),
    );
  });

  it("uses HTTPS only (never HTTP)", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34"]);
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("token", { status: 200 }),
    );

    await verifyHttpChallenge("example.com", "id", "token");

    const calledUrl = fetchSpy.mock.calls[0][0] as string;
    expect(calledUrl).toMatch(/^https:\/\//);
  });

  // ─── Validation ─────────────────────────────────────────────────

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

  // ─── SSRF Prevention ────────────────────────────────────────────

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

    it("falls back to IPv6 when IPv4 resolution fails", async () => {
      mockResolve4.mockRejectedValue(new Error("ENODATA"));
      mockResolve6.mockResolvedValue(["2001:db8::1"]);
      vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response("token", { status: 200 }),
      );

      const result = await verifyHttpChallenge("ipv6only.example", "id", "token");
      expect(result).toBe(true);
    });
  });
});
