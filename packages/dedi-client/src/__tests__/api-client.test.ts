import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DeDiClientError } from "@opencred/shared";
import { DeDiApiClient } from "../api/api-client.js";
import type { DeDiApiClientConfig } from "../api/api-client.js";

function fakeJwt(expSeconds: number): string {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = btoa(JSON.stringify({ exp: expSeconds }));
  return `${header}.${payload}.fake`;
}

function jwtExpiringIn(seconds: number): string {
  return fakeJwt(Math.floor(Date.now() / 1000) + seconds);
}

function createConfig(overrides?: Partial<DeDiApiClientConfig>): DeDiApiClientConfig {
  return {
    baseUrl: "https://dedi.example.com",
    timeoutMs: 5000,
    auth: { type: "api-key", apiKey: "dk_test_key" },
    circuitBreakerThreshold: 5,
    maxRetries: 0,
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("DeDiApiClient", () => {
  const originalFetch = globalThis.fetch;
  let mockFetch: ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockFetch = vi.fn<typeof globalThis.fetch>();
    globalThis.fetch = mockFetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.useRealTimers();
  });

  // ── Auth header injection ────────────────────────────────────────

  describe("auth header injection", () => {
    it("sends Authorization header with API key", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ data: {} }));
      const client = new DeDiApiClient(createConfig());

      await client.getStats();

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: "Bearer dk_test_key",
          }),
        }),
      );
    });

    it("sends Authorization header with bearer token after login", async () => {
      const jwt = jwtExpiringIn(3600);
      // First call: login
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ access_token: jwt, refresh_token: "rt_1", token_type: "bearer" }),
      );
      // Second call: actual API request
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: {} }));

      const client = new DeDiApiClient(
        createConfig({ auth: { type: "bearer", email: "u@t.com", password: "p" } }),
      );
      await client.getStats();

      // Second call should have the JWT
      const [, init] = mockFetch.mock.calls[1]!;
      expect((init?.headers as Record<string, string>)["Authorization"]).toBe(`Bearer ${jwt}`);
    });
  });

  // ── Namespace endpoints ──────────────────────────────────────────

  describe("namespace endpoints", () => {
    it("createNamespace POSTs to /dedi/namespace", async () => {
      const ns = { name: "example.com", description: "Test", state: "active", verified: false, created_at: "", updated_at: "" };
      mockFetch.mockResolvedValue(jsonResponse(ns));

      const client = new DeDiApiClient(createConfig());
      const result = await client.createNamespace("example.com", "Test");

      expect(result).toEqual(ns);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/namespace");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(init?.body as string)).toEqual({ name: "example.com", description: "Test" });
    });

    it("lookupNamespace GETs /dedi/lookup/{ns}", async () => {
      const ns = { name: "example.com", description: "Test", state: "active", verified: false, created_at: "", updated_at: "" };
      mockFetch.mockResolvedValue(jsonResponse(ns));

      const client = new DeDiApiClient(createConfig());
      await client.lookupNamespace("example.com");

      expect(mockFetch.mock.calls[0]![0]).toBe("https://dedi.example.com/dedi/lookup/example.com");
    });
  });

  // ── Registry endpoints ───────────────────────────────────────────

  describe("registry endpoints", () => {
    it("createRegistry POSTs to /dedi/namespace/{ns}/registry", async () => {
      const reg = { name: "revocation_list", namespace: "example.com", schema: {}, tag: "revoke", state: "active", record_count: 0, created_at: "", updated_at: "" };
      mockFetch.mockResolvedValue(jsonResponse(reg));

      const client = new DeDiApiClient(createConfig());
      await client.createRegistry("example.com", "revocation_list", {}, "revoke");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/namespace/example.com/registry");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(init?.body as string)).toEqual({
        name: "revocation_list",
        schema: {},
        tag: "revoke",
      });
    });

    it("lookupRegistry GETs /dedi/lookup/{ns}/{reg}", async () => {
      mockFetch.mockResolvedValue(jsonResponse({}));
      const client = new DeDiApiClient(createConfig());
      await client.lookupRegistry("example.com", "revocation_list");

      expect(mockFetch.mock.calls[0]![0]).toBe(
        "https://dedi.example.com/dedi/lookup/example.com/revocation_list",
      );
    });

    it("revokeRegistry DELETEs /dedi/namespace/{ns}/registry/{reg}", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.revokeRegistry("example.com", "old_list");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/namespace/example.com/registry/old_list");
      expect(init?.method).toBe("DELETE");
    });
  });

  // ── Record endpoints ─────────────────────────────────────────────

  describe("record endpoints", () => {
    it("publishRecord POSTs to /dedi/namespace/{ns}/registry/{reg}/record", async () => {
      const record = { name: "abc", registry: "r", namespace: "ns", detail: {}, state: "live", version: 1, created_at: "", updated_at: "" };
      mockFetch.mockResolvedValue(jsonResponse(record));

      const client = new DeDiApiClient(createConfig());
      await client.publishRecord("ns", "r", "abc", { hash: "abc" });

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/namespace/ns/registry/r/record");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(init?.body as string)).toEqual({ name: "abc", detail: { hash: "abc" } });
    });

    it("lookupRecord GETs /dedi/lookup/{ns}/{reg}/{record}", async () => {
      mockFetch.mockResolvedValue(jsonResponse({}));
      const client = new DeDiApiClient(createConfig());
      await client.lookupRecord("ns", "r", "rec1");

      expect(mockFetch.mock.calls[0]![0]).toBe("https://dedi.example.com/dedi/lookup/ns/r/rec1");
    });

    it("revokeRecord sends state change to revoked", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.revokeRecord("ns", "r", "rec1");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/namespace/ns/registry/r/record/rec1/state");
      expect(init?.method).toBe("PUT");
      expect(JSON.parse(init?.body as string)).toEqual({ state: "revoked" });
    });

    it("changeRecordState PUTs to /dedi/namespace/{ns}/registry/{reg}/record/{name}/state", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.changeRecordState("ns", "r", "rec1", "suspended");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/namespace/ns/registry/r/record/rec1/state");
      expect(JSON.parse(init?.body as string)).toEqual({ state: "suspended" });
    });
  });

  // ── Query & Search ───────────────────────────────────────────────

  describe("query and search", () => {
    it("queryRecords GETs /dedi/namespace/{ns}/registry/{reg}/records with params", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ records: [], total: 0, page: 1, per_page: 20 }));
      const client = new DeDiApiClient(createConfig());
      await client.queryRecords("ns", "r", { page: 2, per_page: 10 });

      const url = mockFetch.mock.calls[0]![0] as string;
      expect(url).toContain("/dedi/namespace/ns/registry/r/records");
      expect(url).toContain("page=2");
      expect(url).toContain("per_page=10");
    });

    it("search GETs /dedi/search/{ns} with query params", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ records: [], total: 0 }));
      const client = new DeDiApiClient(createConfig());
      await client.search("ns", { registry_name: "revocation_list", "detail.hash": "abc" });

      const url = mockFetch.mock.calls[0]![0] as string;
      expect(url).toContain("/dedi/search/ns");
      expect(url).toContain("registry_name=revocation_list");
      expect(url).toContain("detail.hash=abc");
    });
  });

  // ── Domain verification ──────────────────────────────────────────

  describe("domain verification", () => {
    it("generateTxt POSTs to /dedi/namespace/{ns}/verify/generate", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ txt_record: "dedi-verify=abc" }));
      const client = new DeDiApiClient(createConfig());
      const result = await client.generateTxt("ns");

      expect(result).toEqual({ txt_record: "dedi-verify=abc" });
      expect(mockFetch.mock.calls[0]![0]).toBe("https://dedi.example.com/dedi/namespace/ns/verify/generate");
    });

    it("verifyDomain POSTs to /dedi/namespace/{ns}/verify", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.verifyDomain("ns", "example.com");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/namespace/ns/verify");
      expect(JSON.parse(init?.body as string)).toEqual({ domain: "example.com" });
    });

    it("checkVerification GETs /dedi/namespace/{ns}/verify/status", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ verified: true }));
      const client = new DeDiApiClient(createConfig());
      const result = await client.checkVerification("ns");

      expect(result).toEqual({ verified: true });
    });
  });

  // ── Stats (public, no auth) ──────────────────────────────────────

  describe("stats", () => {
    it("getStats GETs /dedi/stats", async () => {
      const stats = { namespaces: 10, registries: 50, records: 1000 };
      mockFetch.mockResolvedValue(jsonResponse(stats));

      const client = new DeDiApiClient(createConfig());
      const result = await client.getStats();

      expect(result).toEqual(stats);
      expect(mockFetch.mock.calls[0]![0]).toBe("https://dedi.example.com/dedi/stats");
    });
  });

  // ── Error handling — sanitization ────────────────────────────────

  describe("error sanitization", () => {
    it("does NOT include response body in error messages on 4xx", async () => {
      mockFetch.mockResolvedValue(
        new Response(JSON.stringify({ secret: "leaked-internal-path" }), { status: 404 }),
      );

      const client = new DeDiApiClient(createConfig());
      const err = await client.lookupNamespace("missing").catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toBe("DeDi API error: 404");
      expect((err as DeDiClientError).message).not.toContain("leaked-internal-path");
    });

    it("does NOT include response body in error messages on 5xx", async () => {
      mockFetch.mockResolvedValue(
        new Response("Internal diagnostic info with tokens", { status: 500 }),
      );

      const client = new DeDiApiClient(createConfig());
      const err = await client.lookupNamespace("broken").catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toBe("DeDi API error: 500");
      expect((err as DeDiClientError).message).not.toContain("diagnostic");
    });

    it("maps 5xx to 502 status code", async () => {
      mockFetch.mockResolvedValue(new Response("error", { status: 503 }));

      const client = new DeDiApiClient(createConfig());
      const err = await client.lookupNamespace("broken").catch((e: unknown) => e);

      expect((err as DeDiClientError).statusCode).toBe(502);
    });
  });

  // ── Timeout ──────────────────────────────────────────────────────

  describe("timeout", () => {
    it("throws on timeout with DeDiClientError", async () => {
      mockFetch.mockImplementation(
        (_url: string | URL | Request, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            if (init?.signal) {
              init.signal.addEventListener("abort", () => {
                reject(new DOMException("The operation was aborted", "AbortError"));
              });
            }
          }),
      );

      const client = new DeDiApiClient(createConfig({ timeoutMs: 50 }));
      const promise = client.getStats().catch((e: unknown) => e);
      await vi.advanceTimersByTimeAsync(60);

      const err = await promise;
      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toMatch(/timed out/);
    });
  });

  // ── Bulk endpoints ───────────────────────────────────────────────

  describe("bulk endpoints", () => {
    it("getJobStatus GETs /dedi/jobs/{jobId}", async () => {
      const job = { job_id: "j1", state: "completed", total: 10, processed: 10, failed: 0, errors: [], created_at: "", updated_at: "" };
      mockFetch.mockResolvedValue(jsonResponse(job));

      const client = new DeDiApiClient(createConfig());
      const result = await client.getJobStatus("j1");

      expect(result).toEqual(job);
      expect(mockFetch.mock.calls[0]![0]).toBe("https://dedi.example.com/dedi/jobs/j1");
    });
  });

  // ── Watch endpoints ──────────────────────────────────────────────

  describe("watch endpoints", () => {
    it("listWatchSubscriptions GETs /dedi/watch", async () => {
      mockFetch.mockResolvedValue(jsonResponse([]));
      const client = new DeDiApiClient(createConfig());
      await client.listWatchSubscriptions();

      expect(mockFetch.mock.calls[0]![0]).toBe("https://dedi.example.com/dedi/watch");
    });

    it("deleteWatch DELETEs /dedi/watch/{subId}", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.deleteWatch("sub123");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/watch/sub123");
      expect(init?.method).toBe("DELETE");
    });
  });

  // ── Network error ────────────────────────────────────────────────

  describe("network error", () => {
    it("wraps network errors in DeDiClientError", async () => {
      mockFetch.mockRejectedValue(new TypeError("fetch failed"));

      const client = new DeDiApiClient(createConfig());
      const err = await client.getStats().catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toBe("DeDi API network error");
    });
  });
});
