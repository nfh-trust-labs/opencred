import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Default mock: every hostname resolves to a public IPv4 address.
// Individual tests override this via the mocked dns module reference.
vi.mock("node:dns", () => ({
  promises: {
    resolve4: vi.fn().mockResolvedValue(["93.184.216.34"]),
    resolve6: vi.fn().mockResolvedValue([]),
  },
}));

// `doFetch` issues its request through `fetchWithPinnedIp` so the addresses
// validated by `assertHostIsPublic` are the ONLY addresses the socket may
// connect to. Route it back through `globalThis.fetch` so the existing stubs
// still observe `(url, init)`; the pinned address set is asserted through the
// mock's own call record.
vi.mock("@opencred/shared", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@opencred/shared")>();
  return {
    ...actual,
    fetchWithPinnedIp: vi.fn(
      async (
        url: string | URL,
        _addresses: readonly string[],
        options?: Record<string, unknown>,
      ): Promise<Response> => globalThis.fetch(url as string, options as RequestInit),
    ),
  };
});

import { promises as dns } from "node:dns";
import { DeDiClientError, fetchWithPinnedIp } from "@opencred/shared";
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

    // Anand's P2-03: the SSRF check used to hit the resolver twice (A+AAAA)
    // on every request. A 30 s per-hostname cache eliminates the DNS round-
    // trip on the hot path while still running isPrivateIP on every request.
    it("caches resolved addresses across requests within the TTL (P2-03)", async () => {
      vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
      vi.mocked(dns.resolve6).mockRejectedValue(
        Object.assign(new Error("ENODATA"), { code: "ENODATA" }),
      );
      // A Response body can only be consumed once, so mint a fresh one per call.
      mockFetch.mockImplementation(async () => publicResponse());

      const client = new DeDiApiClient(baseConfig());
      await client.getStats();
      await client.getStats();
      await client.getStats();

      // Three requests, but exactly one round-trip per resolver.
      expect(vi.mocked(dns.resolve4)).toHaveBeenCalledTimes(1);
      expect(vi.mocked(dns.resolve6)).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it("still rejects cached addresses that turn out to be private (P2-03)", async () => {
      // Seed the cache with a public address on the first request.
      vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
      vi.mocked(dns.resolve6).mockRejectedValue(
        Object.assign(new Error("ENODATA"), { code: "ENODATA" }),
      );
      mockFetch.mockImplementation(async () => publicResponse());

      const client = new DeDiApiClient(baseConfig());
      await client.getStats();

      // Swap the cache entry to a private IP (simulates a post-hoc
      // reconfiguration or a deliberate test of the defense-in-depth
      // isPrivateIP check on cached values).
      const dnsCache: Map<string, { addresses: string[]; resolvedAt: number }> = (
        client as unknown as {
          dnsCache: Map<string, { addresses: string[]; resolvedAt: number }>;
        }
      ).dnsCache;
      dnsCache.set("dedi.example.com", {
        addresses: ["10.0.0.1"],
        resolvedAt: Date.now(),
      });

      const err = await client.getStats().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toMatch(
        /must not target a private, loopback, or link-local IP/,
      );
    });
  });

  // ── DNS-rebinding (TOCTOU) protection ────────────────────────────
  //
  // `assertHostIsPublic` validating DNS and then calling `globalThis.fetch`
  // was only advisory: fetch performs its OWN lookup, so an attacker-run
  // resolver could answer the validation query with a public IP and the
  // connect-time query with 169.254.169.254. The request is now pinned to the
  // addresses that were validated.
  describe("DNS-rebinding protection (connection pinning)", () => {
    it("pins the request to the validated addresses", async () => {
      vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
      mockFetch.mockImplementation(async () => publicResponse());

      const client = new DeDiApiClient(baseConfig());
      await client.getStats();

      expect(vi.mocked(fetchWithPinnedIp)).toHaveBeenCalledTimes(1);
      const [url, addresses] = vi.mocked(fetchWithPinnedIp).mock.calls[0]!;
      // The hostname stays in the URL so TLS SNI + certificate validation run
      // against it — never an IP-in-URL + Host-header "pin".
      expect(String(url)).toBe("https://dedi.example.com/dedi/stats");
      expect(addresses).toEqual(["93.184.216.34"]);
    });

    it("pins the FULL resolved set so multi-A / dual-stack hosts keep failover", async () => {
      vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34", "93.184.216.35"]);
      vi.mocked(dns.resolve6).mockResolvedValue(["2606:2800:220:1:248:1893:25c8:1946"]);
      mockFetch.mockImplementation(async () => publicResponse());

      const client = new DeDiApiClient(baseConfig());
      await client.getStats();

      const [, addresses] = vi.mocked(fetchWithPinnedIp).mock.calls[0]!;
      expect(addresses).toEqual([
        "93.184.216.34",
        "93.184.216.35",
        "2606:2800:220:1:248:1893:25c8:1946",
      ]);
    });

    it("a resolver that rebinds to cloud metadata cannot poison the connection", async () => {
      // First answer public (passes validation), every later answer is the
      // metadata address. Because the connection is pinned and the addresses
      // are cached, the rebound answer is never used.
      vi.mocked(dns.resolve4)
        .mockResolvedValueOnce(["93.184.216.34"])
        .mockResolvedValue(["169.254.169.254"]);
      vi.mocked(dns.resolve6).mockResolvedValue([]);
      mockFetch.mockImplementation(async () => publicResponse());

      const client = new DeDiApiClient(baseConfig());
      await client.getStats();
      await client.getStats();

      expect(vi.mocked(dns.resolve4)).toHaveBeenCalledTimes(1);
      expect(vi.mocked(fetchWithPinnedIp)).toHaveBeenCalledTimes(2);
      for (const [, addresses] of vi.mocked(fetchWithPinnedIp).mock.calls) {
        expect(addresses).toEqual(["93.184.216.34"]);
        expect(addresses).not.toContain("169.254.169.254");
      }
    });

    it("never reaches the pinned fetch when the host resolves to a private IP", async () => {
      vi.mocked(dns.resolve4).mockResolvedValue(["169.254.169.254"]);
      const client = new DeDiApiClient(baseConfig());

      const err = await client.getStats().catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toMatch(/private, loopback/);
      expect(vi.mocked(fetchWithPinnedIp)).not.toHaveBeenCalled();
    });

    it("pins a literal public IP host to itself", async () => {
      mockFetch.mockImplementation(async () => publicResponse());
      const client = new DeDiApiClient(baseConfig({ baseUrl: "https://93.184.216.34" }));

      await client.getStats();

      const [, addresses] = vi.mocked(fetchWithPinnedIp).mock.calls[0]!;
      expect(addresses).toEqual(["93.184.216.34"]);
      // No DNS lookup for a literal IP.
      expect(vi.mocked(dns.resolve4)).not.toHaveBeenCalled();
    });
  });

  describe("fetch hardening", () => {
    it("refuses to follow redirects (surfaced as a 502 network error)", async () => {
      // `https.request` never follows redirects, so a 3xx comes back as a
      // response rather than a thrown fetch error. `doFetch` converts it to
      // the same 502 network error the old `redirect: "error"` produced.
      mockFetch.mockResolvedValue(new Response(null, { status: 302 }));
      const client = new DeDiApiClient(baseConfig());

      const err = await client.getStats().catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).statusCode).toBe(502);
      expect((err as DeDiClientError).message).toMatch(/redirect/i);
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

    // `fetch` rejects an abort with a DOMException; `https.request` rejects
    // with Node's own AbortError (a plain Error carrying `code: ABORT_ERR`).
    // Verified empirically against Node 26. A DOMException-only check would
    // silently downgrade every DeDi timeout from 504 to a 502 network error.
    it("maps Node's non-DOMException AbortError to a 504 timeout", async () => {
      vi.useFakeTimers();
      try {
        mockFetch.mockImplementation(
          (_url: string | URL | Request, init?: RequestInit) =>
            new Promise<Response>((_resolve, reject) => {
              init?.signal?.addEventListener("abort", () => {
                const abortError = Object.assign(new Error("This operation was aborted"), {
                  name: "AbortError",
                  code: "ABORT_ERR",
                });
                reject(abortError);
              });
            }),
        );
        const client = new DeDiApiClient(baseConfig({ timeoutMs: 50 }));
        const promise = client.getStats().catch((e: unknown) => e);
        await vi.advanceTimersByTimeAsync(100);
        const err = await promise;
        expect(err).toBeInstanceOf(DeDiClientError);
        expect((err as DeDiClientError).statusCode).toBe(504);
        expect((err as DeDiClientError).message).toMatch(/timed out after 50ms/);
      } finally {
        vi.useRealTimers();
      }
    });
  });
});
