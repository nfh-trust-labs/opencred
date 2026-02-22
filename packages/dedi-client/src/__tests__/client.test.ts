import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DeDiClientError } from "@opencred/shared";
import { DeDiClient } from "../client.js";

function createClient() {
  return new DeDiClient({
    baseUrl: "https://dedi.example.com/api",
    timeoutMs: 5000,
    maxRetries: 0,
    circuitBreakerThreshold: 5,
  });
}

const mockRevocation = { hash: "abc123", revoked: false };
const mockDID = {
  did: "did:key:z6Mk...",
  document: { id: "did:key:z6Mk..." },
  resolvedAt: "2026-01-01T00:00:00Z",
};
const mockDelegation = {
  id: "del-1",
  issuerDid: "did:key:issuer",
  delegateDid: "did:key:delegate",
  scope: ["issue"],
  validFrom: "2026-01-01T00:00:00Z",
  validUntil: "2027-01-01T00:00:00Z",
  certificate: {},
};

describe("DeDiClient", () => {
  const originalFetch = globalThis.fetch;
  let mockFetch: ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

  beforeEach(() => {
    mockFetch = vi.fn<typeof globalThis.fetch>();
    globalThis.fetch = mockFetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe("publishRevocationHash", () => {
    it("POSTs a revocation hash", async () => {
      mockFetch.mockResolvedValue(new Response(JSON.stringify(mockRevocation), { status: 200 }));

      const client = createClient();
      const result = await client.publishRevocationHash("abc123");

      expect(result).toEqual(mockRevocation);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://dedi.example.com/api/revocations",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ hash: "abc123" }),
        }),
      );
    });
  });

  describe("queryRevocationHash", () => {
    it("GETs a revocation status", async () => {
      mockFetch.mockResolvedValue(new Response(JSON.stringify(mockRevocation), { status: 200 }));

      const client = createClient();
      const result = await client.queryRevocationHash("abc123");

      expect(result).toEqual(mockRevocation);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://dedi.example.com/api/revocations/abc123",
        expect.objectContaining({ signal: expect.any(AbortSignal) }),
      );
    });
  });

  describe("resolveDID", () => {
    it("GETs a DID document", async () => {
      mockFetch.mockResolvedValue(new Response(JSON.stringify(mockDID), { status: 200 }));

      const client = createClient();
      const result = await client.resolveDID("did:key:z6Mk...");

      expect(result).toEqual(mockDID);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://dedi.example.com/api/dids/did%3Akey%3Az6Mk...",
        expect.objectContaining({ signal: expect.any(AbortSignal) }),
      );
    });
  });

  describe("registerDelegation", () => {
    it("POSTs a delegation certificate", async () => {
      mockFetch.mockResolvedValue(new Response(JSON.stringify(mockDelegation), { status: 200 }));

      const client = createClient();
      const delegation = { issuerDid: "did:key:issuer", scope: ["issue"] };
      const result = await client.registerDelegation(delegation);

      expect(result).toEqual(mockDelegation);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://dedi.example.com/api/delegations",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify(delegation),
        }),
      );
    });
  });

  describe("resolveDelegation", () => {
    it("GETs a delegation record", async () => {
      mockFetch.mockResolvedValue(new Response(JSON.stringify(mockDelegation), { status: 200 }));

      const client = createClient();
      const result = await client.resolveDelegation("del-1");

      expect(result).toEqual(mockDelegation);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://dedi.example.com/api/delegations/del-1",
        expect.objectContaining({ signal: expect.any(AbortSignal) }),
      );
    });
  });

  describe("error handling", () => {
    it("throws DeDiClientError on 4xx response", async () => {
      mockFetch.mockResolvedValue(
        new Response(JSON.stringify({ error: "not found" }), { status: 404 }),
      );

      const client = createClient();
      await expect(client.queryRevocationHash("missing")).rejects.toThrow(DeDiClientError);
      await expect(client.queryRevocationHash("missing")).rejects.toMatchObject({
        statusCode: 404,
      });
    });

    it("throws DeDiClientError with 502 on 5xx response", async () => {
      mockFetch.mockResolvedValue(new Response("Internal Server Error", { status: 500 }));

      const client = createClient();
      await expect(client.resolveDID("did:key:abc")).rejects.toThrow(DeDiClientError);
      await expect(client.resolveDID("did:key:abc")).rejects.toMatchObject({
        statusCode: 502,
      });
    });

    it("throws DeDiClientError on network failure", async () => {
      mockFetch.mockRejectedValue(new TypeError("fetch failed"));

      const client = createClient();
      await expect(client.resolveDID("did:key:abc")).rejects.toThrow(DeDiClientError);
      await expect(client.resolveDID("did:key:abc")).rejects.toThrow("DeDi API network error");
    });

    it("throws DeDiClientError on timeout", async () => {
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

      const client = new DeDiClient({
        baseUrl: "https://dedi.example.com/api",
        timeoutMs: 50,
        maxRetries: 0,
        circuitBreakerThreshold: 5,
      });

      const error = await client.resolveDID("did:key:abc").catch((e: unknown) => e);
      expect(error).toBeInstanceOf(DeDiClientError);
      expect((error as DeDiClientError).message).toMatch(/timed out/);
    });
  });

  describe("retry + circuit breaker integration", () => {
    it("retries on transient errors and succeeds", async () => {
      mockFetch
        .mockResolvedValueOnce(new Response("error", { status: 500 }))
        .mockResolvedValue(new Response(JSON.stringify(mockRevocation), { status: 200 }));

      vi.useFakeTimers();
      const client = new DeDiClient({
        baseUrl: "https://dedi.example.com/api",
        timeoutMs: 5000,
        maxRetries: 2,
        circuitBreakerThreshold: 5,
      });

      const promise = client.queryRevocationHash("abc123");
      await vi.advanceTimersByTimeAsync(200);
      const result = await promise;

      expect(result).toEqual(mockRevocation);
      expect(mockFetch).toHaveBeenCalledTimes(2);
      vi.useRealTimers();
    });

    it("opens circuit breaker after repeated failures", async () => {
      mockFetch.mockResolvedValue(new Response("error", { status: 500 }));

      const client = new DeDiClient({
        baseUrl: "https://dedi.example.com/api",
        timeoutMs: 5000,
        maxRetries: 0,
        circuitBreakerThreshold: 2,
      });

      await expect(client.resolveDID("did:key:a")).rejects.toThrow(DeDiClientError);
      await expect(client.resolveDID("did:key:b")).rejects.toThrow(DeDiClientError);
      // Circuit is now open — should reject without calling fetch
      const callCount = mockFetch.mock.calls.length;
      await expect(client.resolveDID("did:key:c")).rejects.toThrow("Circuit breaker is open");
      expect(mockFetch).toHaveBeenCalledTimes(callCount);
    });
  });
});
