import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock node:dns so tests do not perform real DNS lookups. The default
// mock resolves every hostname to a public IPv4 address; tests that
// exercise SSRF behaviour override this via vi.mocked() or spyOn.
vi.mock("node:dns", () => ({
  promises: {
    resolve4: vi.fn().mockResolvedValue(["93.184.216.34"]),
    resolve6: vi.fn().mockResolvedValue([]),
  },
}));
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

  // ── HTTPS enforcement ────────────────────────────────────────────

  describe("HTTPS enforcement", () => {
    it("rejects http:// URLs regardless of NODE_ENV", () => {
      const originalNodeEnv = process.env.NODE_ENV;
      try {
        for (const env of ["production", "development", "test", undefined]) {
          if (env === undefined) delete process.env.NODE_ENV;
          else process.env.NODE_ENV = env;
          expect(
            () => new DeDiApiClient(createConfig({ baseUrl: "http://dedi.example.com" })),
          ).toThrow(DeDiClientError);
        }
      } finally {
        process.env.NODE_ENV = originalNodeEnv;
      }
    });

    it("rejects non-HTTP schemes such as ftp://", () => {
      expect(() => new DeDiApiClient(createConfig({ baseUrl: "ftp://dedi.example.com" }))).toThrow(
        /HTTPS/,
      );
    });

    it("rejects malformed URLs", () => {
      expect(() => new DeDiApiClient(createConfig({ baseUrl: "not-a-url" }))).toThrow(
        DeDiClientError,
      );
    });

    it("accepts https:// URLs", () => {
      expect(
        () => new DeDiApiClient(createConfig({ baseUrl: "https://dedi.example.com" })),
      ).not.toThrow();
    });
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
      const ns = {
        name: "example.com",
        description: "Test",
        state: "active",
        verified: false,
        created_at: "",
        updated_at: "",
      };
      mockFetch.mockResolvedValue(jsonResponse(ns));

      const client = new DeDiApiClient(createConfig());
      const result = await client.createNamespace("example.com", "Test");

      expect(result).toEqual(ns);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/create-namespace");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(init?.body as string)).toEqual({
        name: "example.com",
        description: "Test",
        meta: {},
      });
    });

    it("createNamespace does NOT retry on 5xx (issue #546)", async () => {
      // Without retryable:false, maxRetries:3 would trigger 4 POSTs and
      // create up to 4 duplicate namespaces on the user's DeDi account.
      mockFetch.mockResolvedValue(new Response("upstream error", { status: 500, headers: {} }));

      const client = new DeDiApiClient(createConfig({ maxRetries: 3 }));
      await expect(client.createNamespace("example.com", "Test")).rejects.toThrow();

      // Exactly one call — no retry loop on this non-idempotent POST.
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("createNamespace surfaces JSON body on error.responseBody", async () => {
      // The adapter layer needs to read response body codes like
      // NAMESPACE_EXISTS to dedupe across 4xx variants.
      mockFetch.mockResolvedValue(
        new Response(JSON.stringify({ code: "NAMESPACE_EXISTS" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }),
      );

      const client = new DeDiApiClient(createConfig());
      let caught: unknown;
      try {
        await client.createNamespace("example.com", "Test");
      } catch (err) {
        caught = err;
      }

      expect(caught).toBeInstanceOf(DeDiClientError);
      expect((caught as DeDiClientError).statusCode).toBe(400);
      expect((caught as DeDiClientError).responseBody).toEqual({ code: "NAMESPACE_EXISTS" });
    });

    it("lookupNamespace GETs /dedi/lookup/{ns}", async () => {
      const ns = {
        name: "example.com",
        description: "Test",
        state: "active",
        verified: false,
        created_at: "",
        updated_at: "",
      };
      mockFetch.mockResolvedValue(jsonResponse(ns));

      const client = new DeDiApiClient(createConfig());
      await client.lookupNamespace("example.com");

      expect(mockFetch.mock.calls[0]![0]).toBe("https://dedi.example.com/dedi/lookup/example.com");
    });
  });

  // ── Registry endpoints ───────────────────────────────────────────

  describe("registry endpoints", () => {
    it("createRegistry POSTs to /dedi/{ns}/create-registry", async () => {
      const reg = {
        name: "revocation_list",
        namespace: "example.com",
        schema: {},
        tag: "custom",
        state: "active",
        record_count: 0,
        created_at: "",
        updated_at: "",
      };
      mockFetch.mockResolvedValue(jsonResponse(reg));

      const schema = {
        $schema: "http://json-schema.org/draft-07/schema#",
        type: "object",
        properties: {},
      };
      const client = new DeDiApiClient(createConfig());
      await client.createRegistry("example.com", "revocation_list", schema);

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/example.com/create-registry");
      expect(init?.method).toBe("POST");
      const body = JSON.parse(init?.body as string);
      expect(body.registry_name).toBe("revocation_list");
      expect(body.schema).toEqual(schema);
      expect(body.tag).toBeUndefined();
    });

    it("lookupRegistry GETs /dedi/lookup/{ns}/{reg}", async () => {
      mockFetch.mockResolvedValue(jsonResponse({}));
      const client = new DeDiApiClient(createConfig());
      await client.lookupRegistry("example.com", "revocation_list");

      expect(mockFetch.mock.calls[0]![0]).toBe(
        "https://dedi.example.com/dedi/lookup/example.com/revocation_list",
      );
    });

    it("revokeRegistry POSTs to /dedi/{ns}/{reg}/revoke-registry", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.revokeRegistry("example.com", "old_list");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/example.com/old_list/revoke-registry");
      expect(init?.method).toBe("POST");
    });
  });

  // ── Record endpoints ─────────────────────────────────────────────

  describe("record endpoints", () => {
    it("publishRecord POSTs to /dedi/{ns}/{reg}/save-record-as-draft?publish=true", async () => {
      const envelope = {
        message: "Record published",
        data: {
          record_name: "abc",
          registry: "r",
          namespace: "ns",
          details: {},
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      };
      mockFetch.mockResolvedValue(jsonResponse(envelope));

      const client = new DeDiApiClient(createConfig());
      const result = await client.publishRecord("ns", "r", "abc", { hash: "abc" });

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/ns/r/save-record-as-draft?publish=true");
      expect(init?.method).toBe("POST");
      const body = JSON.parse(init?.body as string);
      expect(body.record_name).toBe("abc");
      expect(body.details).toEqual({ hash: "abc" });
      // The api-client returns the envelope verbatim; adapter unwraps.
      expect(result).toEqual(envelope);
    });

    it("lookupRecord GETs /dedi/lookup/{ns}/{reg}/{record}", async () => {
      mockFetch.mockResolvedValue(jsonResponse({}));
      const client = new DeDiApiClient(createConfig());
      await client.lookupRecord("ns", "r", "rec1");

      expect(mockFetch.mock.calls[0]![0]).toBe("https://dedi.example.com/dedi/lookup/ns/r/rec1");
    });

    it("revokeRecord POSTs to /dedi/{ns}/{reg}/{rec}/revoke-record", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.revokeRecord("ns", "r", "rec1");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/ns/r/rec1/revoke-record");
      expect(init?.method).toBe("POST");
    });

    it("changeRecordState POSTs to /dedi/{ns}/{reg}/{rec}/{action}", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.changeRecordState("ns", "r", "rec1", "suspended");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/ns/r/rec1/suspend-record");
      expect(init?.method).toBe("POST");
    });
  });

  // ── Query & Search ───────────────────────────────────────────────

  describe("query and search", () => {
    it("queryRecords GETs /dedi/query/{ns}/{reg} with params", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ message: "ok", data: [] }));
      const client = new DeDiApiClient(createConfig());
      const result = await client.queryRecords("ns", "r", { page: 2, per_page: 10 });

      const url = mockFetch.mock.calls[0]![0] as string;
      expect(url).toContain("/dedi/query/ns/r");
      expect(url).toContain("page=2");
      expect(url).toContain("per_page=10");
      expect(result).toEqual({ message: "ok", data: [] });
    });

    it("search GETs /dedi/search/{ns} with query params", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ message: "ok", data: [] }));
      const client = new DeDiApiClient(createConfig());
      const result = await client.search("ns", {
        registry_name: "revocation_list",
        "detail.hash": "abc",
      });

      const url = mockFetch.mock.calls[0]![0] as string;
      expect(url).toContain("/dedi/search/ns");
      expect(url).toContain("registry_name=revocation_list");
      expect(url).toContain("detail.hash=abc");
      expect(result).toEqual({ message: "ok", data: [] });
    });
  });

  // ── Domain verification ──────────────────────────────────────────

  describe("domain verification", () => {
    it("generateTxt GETs /dedi/generate-dns-txt/{ns}/{domain}", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ txt_record: "dedi-verify=abc" }));
      const client = new DeDiApiClient(createConfig());
      const result = await client.generateTxt("ns", "example.com");

      expect(result).toEqual({ txt_record: "dedi-verify=abc" });
      expect(mockFetch.mock.calls[0]![0]).toBe(
        "https://dedi.example.com/dedi/generate-dns-txt/ns/example.com",
      );
    });

    it("verifyDomain POSTs to /dedi/verify-domain", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.verifyDomain("ns");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/verify-domain");
      expect(JSON.parse(init?.body as string)).toEqual({ namespace_id: "ns" });
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
      const job = {
        job_id: "j1",
        state: "completed",
        total: 10,
        processed: 10,
        failed: 0,
        errors: [],
        created_at: "",
        updated_at: "",
      };
      mockFetch.mockResolvedValue(jsonResponse(job));

      const client = new DeDiApiClient(createConfig());
      const result = await client.getJobStatus("j1");

      expect(result).toEqual(job);
      expect(mockFetch.mock.calls[0]![0]).toBe(
        "https://dedi.example.com/dedi/bulk-upload/status/j1",
      );
    });
  });

  // ── Watch endpoints ──────────────────────────────────────────────

  describe("watch endpoints", () => {
    it("listWatchSubscriptions GETs /dedi/watch", async () => {
      mockFetch.mockResolvedValue(jsonResponse([]));
      const client = new DeDiApiClient(createConfig());
      await client.listWatchSubscriptions();

      expect(mockFetch.mock.calls[0]![0]).toBe("https://dedi.example.com/dedi/subscriptions");
    });

    it("deleteWatch POSTs to /dedi/unsubscribe", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.deleteWatch("sub123");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/unsubscribe");
      expect(init?.method).toBe("POST");
    });
  });

  // ── Network error ────────────────────────────────────────────────

  describe("network error", () => {
    it("wraps network errors in DeDiClientError and preserves original message", async () => {
      mockFetch.mockRejectedValue(new TypeError("fetch failed"));

      const client = new DeDiApiClient(createConfig());
      const err = await client.getStats().catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toBe("DeDi API network error: fetch failed");
      expect((err as DeDiClientError).statusCode).toBe(502);
    });

    it("handles non-Error thrown values gracefully", async () => {
      mockFetch.mockRejectedValue("string error");

      const client = new DeDiApiClient(createConfig());
      const err = await client.getStats().catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toBe("DeDi API network error: unknown");
    });
  });

  // ── Non-JSON response handling ──────────────────────────────────

  describe("non-JSON response handling", () => {
    it("throws DeDiClientError with 502 for non-JSON (HTML) response", async () => {
      mockFetch.mockResolvedValue(
        new Response("<html>Bad Gateway</html>", {
          status: 200,
          headers: { "Content-Type": "text/html" },
        }),
      );

      const client = new DeDiApiClient(createConfig());
      const err = await client.getStats().catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toBe("DeDi API returned non-JSON response");
      expect((err as DeDiClientError).statusCode).toBe(502);
    });
  });

  // ── bulkUpload ─────────────────────────────────────────────────

  describe("bulkUpload", () => {
    it("POSTs to /dedi/bulk-upload with auth header and required form fields", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ message: "Job queued", data: { jobId: "j1" } }));

      const client = new DeDiApiClient(createConfig());
      const file = new Blob(["col1,col2\na,b"], { type: "text/csv" });
      const result = await client.bulkUpload("ns", "r", file);

      // Response is unwrapped: `data.jobId` becomes `{ jobId }`.
      expect(result).toEqual({ jobId: "j1" });
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/bulk-upload");
      expect(init?.method).toBe("POST");
      expect((init?.headers as Record<string, string>)["Authorization"]).toBe("Bearer dk_test_key");
      expect(init?.body).toBeInstanceOf(FormData);
      // The DeDi API requires `namespace` and `registry_name` alongside
      // the `file` field — verified against the develop Postman
      // collection, 2026-05-19.
      const fd = init?.body as FormData;
      expect(fd.get("namespace")).toBe("ns");
      expect(fd.get("registry_name")).toBe("r");
      // record_name_field is optional — not set in this call.
      expect(fd.get("record_name_field")).toBeNull();
    });

    it("includes record_name_field when provided", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ message: "Job queued", data: { jobId: "j1" } }));

      const client = new DeDiApiClient(createConfig());
      await client.bulkUpload("ns", "r", new Blob(["a,b\n1,2"]), "col1");

      const init = mockFetch.mock.calls[0]![1]!;
      const fd = init.body as FormData;
      expect(fd.get("record_name_field")).toBe("col1");
    });

    it("throws when bulk-upload response is missing data.jobId", async () => {
      mockFetch.mockResolvedValue(jsonResponse({ message: "ok", data: {} }));

      const client = new DeDiApiClient(createConfig());
      const err = await client.bulkUpload("ns", "r", new Blob(["data"])).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toBe(
        "DeDi API bulk upload response missing required field: data.jobId",
      );
    });

    it("throws DeDiClientError on 4xx/5xx", async () => {
      mockFetch.mockResolvedValue(new Response("error", { status: 400 }));

      const client = new DeDiApiClient(createConfig());
      const err = await client.bulkUpload("ns", "r", new Blob(["data"])).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toBe("DeDi API error: 400");
    });

    it("throws on timeout", async () => {
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
      const promise = client.bulkUpload("ns", "r", new Blob(["data"])).catch((e: unknown) => e);
      await vi.advanceTimersByTimeAsync(60);

      const err = await promise;
      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toMatch(/timed out/);
      expect((err as DeDiClientError).statusCode).toBe(504);
    });

    it("preserves original error message on network failure", async () => {
      mockFetch.mockRejectedValue(new TypeError("network down"));

      const client = new DeDiApiClient(createConfig());
      const err = await client.bulkUpload("ns", "r", new Blob(["data"])).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(DeDiClientError);
      expect((err as DeDiClientError).message).toBe("DeDi API network error: network down");
    });

    it("rebuilds FormData on each retry attempt", async () => {
      // First call fails, second succeeds
      mockFetch
        .mockRejectedValueOnce(new TypeError("transient failure"))
        .mockResolvedValueOnce(jsonResponse({ message: "ok", data: { jobId: "j2" } }));

      const client = new DeDiApiClient(createConfig({ maxRetries: 1 }));
      const promise = client.bulkUpload("ns", "r", new Blob(["data"]));

      // Advance past retry backoff delay (200ms base * 2^0 = 200ms)
      await vi.advanceTimersByTimeAsync(300);

      const result = await promise;
      expect(result).toEqual({ jobId: "j2" });
      expect(mockFetch).toHaveBeenCalledTimes(2);
      // Each call should have its own FormData instance
      const body1 = mockFetch.mock.calls[0]![1]?.body;
      const body2 = mockFetch.mock.calls[1]![1]?.body;
      expect(body1).toBeInstanceOf(FormData);
      expect(body2).toBeInstanceOf(FormData);
      expect(body1).not.toBe(body2);
    });
  });

  // ── createWatch ────────────────────────────────────────────────

  describe("createWatch", () => {
    it("POSTs to /dedi/watch with params", async () => {
      const sub = {
        subscription_id: "s1",
        namespace: "ns",
        callback_url: "https://cb.example.com",
        events: ["record.created"],
        created_at: "",
      };
      mockFetch.mockResolvedValue(jsonResponse(sub));

      const client = new DeDiApiClient(createConfig());
      const result = await client.createWatch({
        namespace: "ns",
        callback_url: "https://cb.example.com",
        events: ["record.created"],
      });

      expect(result).toEqual(sub);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/subscribe");
      expect(init?.method).toBe("POST");
    });
  });

  // ── Delegation endpoints ──────────────────────────────────────

  describe("delegation endpoints", () => {
    it("addDelegate POSTs to /dedi/namespace/{ns}/registry/{reg}/delegate", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.addDelegate("ns", "r", "user@example.com");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/ns/r/add-delegate");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(init?.body as string)).toEqual({ email: "user@example.com" });
    });

    it("removeDelegate POSTs to /dedi/{ns}/{reg}/remove-registry-delegate", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      await client.removeDelegate("ns", "r", "user+tag@example.com");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/ns/r/remove-registry-delegate");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(init?.body as string)).toEqual({ email: "user+tag@example.com" });
    });
  });

  // ── verifyRecordLookup ─────────────────────────────────────────

  describe("verifyRecordLookup", () => {
    it("POSTs to /dedi/verify-record-lookup with wrapped payload", async () => {
      mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
      const client = new DeDiApiClient(createConfig());
      const lookupResponse = { name: "rec1", registry: "r", namespace: "ns" };
      await client.verifyRecordLookup(lookupResponse);

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/verify-record-lookup");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(init?.body as string)).toEqual({ record_lookup_response: lookupResponse });
    });
  });
});
