import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock node:dns at the module level before any imports that use it
const mockResolveTxt = vi.fn<(domain: string) => Promise<string[][]>>();
const mockResolverResolveTxt = vi.fn<
  (domain: string, cb: (err: Error | null, addresses: string[][]) => void) => void
>();
const mockSetServers = vi.fn();

vi.mock("node:dns", () => {
  return {
    default: {
      promises: {
        resolveTxt: (...args: Parameters<typeof mockResolveTxt>) => mockResolveTxt(...args),
      },
      Resolver: class MockResolver {
        setServers = mockSetServers;
        resolveTxt = mockResolverResolveTxt;
      },
    },
  };
});

import { verifyDnsTxtChallenge } from "../dns-verifier.js";

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

  it("handles chunked TXT records (concatenates chunks)", async () => {
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

  it("returns false when default resolver matches but secondary does not (cache poisoning mitigation)", async () => {
    mockResolveTxt.mockResolvedValue([["opencred-verify=abc123"]]);
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, [["opencred-verify=different-token"]]);
    });

    const result = await verifyDnsTxtChallenge("example.com", "abc123");

    expect(result).toBe(false);
  });

  it("returns false when secondary resolver matches but default does not", async () => {
    mockResolveTxt.mockResolvedValue([["opencred-verify=wrong"]]);
    mockResolverResolveTxt.mockImplementation((_domain, cb) => {
      cb(null, [["opencred-verify=abc123"]]);
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
