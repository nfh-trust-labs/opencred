import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Default mock: every hostname resolves to a public IPv4 address.
// Individual tests override this via the mocked dns module reference.
vi.mock("node:dns", () => ({
  promises: {
    resolve4: vi.fn().mockResolvedValue(["93.184.216.34"]),
    resolve6: vi.fn().mockResolvedValue([]),
  },
}));

import { promises as dns } from "node:dns";
import { DeDiClientError } from "@opencred/shared";
import { DeDiApiClient } from "../api/api-client.js";
import type { DeDiApiClientConfig } from "../api/api-client.js";

function baseConfig(overrides?: Partial<DeDiApiClientConfig>): DeDiApiClientConfig {
  return {
    baseUrl: "https://dedi.example.com",
    timeoutMs: 5000,
    auth: { type: "api-key", apiKey: "dk_test_key" },
    circuitBreakerThreshold: 5,
    maxRetries: 0,
    ...overrides,
  };
}

function publicResponse(): Response {
  return new Response(JSON.stringify({ namespaces: 1, registries: 1, records: 1 }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("DeDiApiClient SSRF and HTTPS protection", () => {
  const originalFetch = globalThis.fetch;
  let mockFetch: ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

  beforeEach(() => {
    mockFetch = vi.fn<typeof globalThis.fetch>();
    globalThis.fetch = mockFetch;
    // Reset DNS mock to default "public" response between cases.
    vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
    vi.mocked(dns.resolve6).mockResolvedValue([]);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.clearAllMocks();
  });

  describe("HTTPS enforcement", () => {
    it("rejects http:// at construction time", () => {
      expect(() => new DeDiApiClient(baseConfig({ baseUrl: "http://dedi.example.com" }))).toThrow(
        DeDiClientError,
      );
    });

    it("rejects http:// even when NODE_ENV=development (no bypass)", () => {
      const original = process.env.NODE_ENV;
      process.env.NODE_ENV = "development";
      try {
        expect(() => new DeDiApiClient(baseConfig({ baseUrl: "http://dedi.example.com" }))).toThrow(
          /HTTPS/,
        );
      } finally {
        process.env.NODE_ENV = original;
      }
    });

    it("rejects http:// even when NODE_ENV=test (no bypass)", () => {
      const original = process.env.NODE_ENV;
      process.env.NODE_ENV = "test";
      try {
        expect(() => new DeDiApiClient(baseConfig({ baseUrl: "http://dedi.example.com" }))).toThrow(
          /HTTPS/,
        );
      } finally {
        process.env.NODE_ENV = original;
      }
    });

    it("rejects file:// and other non-HTTPS schemes", () => {
      expect(() => new DeDiApiClient(baseConfig({ baseUrl: "file:///etc/passwd" }))).toThrow(
        DeDiClientError,
      );
      expect(() => new DeDiApiClient(baseConfig({ baseUrl: "ftp://dedi.example.com" }))).toThrow(
        DeDiClientError,
      );
    });
  });

  describe("literal IP SSRF protection (constructor)", () => {
    it.each([
      ["https://127.0.0.1", "IPv4 loopback"],
      ["https://10.0.0.5", "IPv4 RFC 1918 10.x"],
      ["https://192.168.1.1", "IPv4 RFC 1918 192.168.x"],
      ["https://172.16.0.5", "IPv4 RFC 1918 172.16-31"],
      ["https://169.254.169.254", "IPv4 link-local / cloud metadata"],
      ["https://0.0.0.0", "IPv4 unspecified"],
      ["https://[::1]", "IPv6 loopback"],
      ["https://[fc00::1]", "IPv6 unique-local"],
      ["https://[fe80::1]", "IPv6 link-local"],
      ["https://[::ffff:127.0.0.1]", "IPv4-mapped IPv6 loopback"],
      ["https://[::ffff:10.0.0.1]", "IPv4-mapped IPv6 RFC 1918"],
    ])("rejects %s (%s)", (baseUrl) => {
      expect(() => new DeDiApiClient(baseConfig({ baseUrl }))).toThrow(
        /private, loopback, or link-local/,
      );
    });

    it("accepts https:// with a literal public IPv4 address", () => {
      expect(
        () => new DeDiApiClient(baseConfig({ baseUrl: "https://93.184.216.34" })),
      ).not.toThrow();
    });
  });

  describe("DNS-resolved SSRF protection (per-request)", () => {
    it("rejects a request when the hostname resolves to 127.0.0.1", async () => {
      vi.mocked(dns.resolve4).mockResolvedValue(["127.0.0.1"]);
      const client = new DeDiApiClient(baseConfig());
      const err = await client.getStats().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toMatch(/private, loopback/);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("rejects a request when hostname resolves to an IPv6 loopback", async () => {
      vi.mocked(dns.resolve4).mockResolvedValue([]);
      vi.mocked(dns.resolve6).mockResolvedValue(["::1"]);
      const client = new DeDiApiClient(baseConfig());
      const err = await client.getStats().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toMatch(/private, loopback/);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("rejects when any resolved address is private (mixed public + private)", async () => {
      vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34", "10.0.0.1"]);
      const client = new DeDiApiClient(baseConfig());
      const err = await client.getStats().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(DeDiClientError);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("rejects when hostname does not resolve at all", async () => {
      vi.mocked(dns.resolve4).mockRejectedValue(new Error("ENOTFOUND"));
      vi.mocked(dns.resolve6).mockRejectedValue(new Error("ENOTFOUND"));
      const client = new DeDiApiClient(baseConfig());
      const err = await client.getStats().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toMatch(/did not resolve/);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("also guards bulkUpload (not just regular requests)", async () => {
      vi.mocked(dns.resolve4).mockResolvedValue(["192.168.1.1"]);
      const client = new DeDiApiClient(baseConfig());
      const err = await client.bulkUpload("ns", "r", new Blob(["data"])).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(DeDiClientError);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("proceeds when the hostname resolves to a public address", async () => {
      vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
      mockFetch.mockResolvedValue(publicResponse());
      const client = new DeDiApiClient(baseConfig());
      await expect(client.getStats()).resolves.toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  describe("fetch hardening", () => {
    it("passes redirect: error to fetch", async () => {
      mockFetch.mockResolvedValue(publicResponse());
      const client = new DeDiApiClient(baseConfig());
      await client.getStats();
      const [, init] = mockFetch.mock.calls[0]!;
      expect(init?.redirect).toBe("error");
    });

    it("caps the effective timeout at 10 seconds even when configured higher", async () => {
      vi.useFakeTimers();
      try {
        mockFetch.mockImplementation(
          (_url: string | URL | Request, init?: RequestInit) =>
            new Promise<Response>((_resolve, reject) => {
              init?.signal?.addEventListener("abort", () => {
                reject(new DOMException("The operation was aborted", "AbortError"));
              });
            }),
        );
        const client = new DeDiApiClient(baseConfig({ timeoutMs: 60_000 }));
        const promise = client.getStats().catch((e: unknown) => e);
        await vi.advanceTimersByTimeAsync(10_001);
        const err = await promise;
        expect(err).toBeInstanceOf(DeDiClientError);
        expect((err as DeDiClientError).message).toMatch(/timed out after 10000ms/);
      } finally {
        vi.useRealTimers();
      }
    });

    it("honours a shorter configured timeout (50ms)", async () => {
      vi.useFakeTimers();
      try {
        mockFetch.mockImplementation(
          (_url: string | URL | Request, init?: RequestInit) =>
            new Promise<Response>((_resolve, reject) => {
              init?.signal?.addEventListener("abort", () => {
                reject(new DOMException("The operation was aborted", "AbortError"));
              });
            }),
        );
        const client = new DeDiApiClient(baseConfig({ timeoutMs: 50 }));
        const promise = client.getStats().catch((e: unknown) => e);
        await vi.advanceTimersByTimeAsync(100);
        const err = await promise;
        expect(err).toBeInstanceOf(DeDiClientError);
        expect((err as DeDiClientError).message).toMatch(/timed out after 50ms/);
      } finally {
        vi.useRealTimers();
      }
    });
  });
});
