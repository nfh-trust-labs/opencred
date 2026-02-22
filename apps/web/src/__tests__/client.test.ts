import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { OpenCredClient } from "../api/client";

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

function jsonResponse(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
  });
}

describe("OpenCredClient", () => {
  it("sends build request with auth header", async () => {
    const client = new OpenCredClient("http://localhost:3000", "test-token");
    mockFetch.mockReturnValue(
      jsonResponse(
        {
          sessionId: "abc-123",
          unsignedCredential: {},
          dataToSign: "AQID",
          proofConfig: {},
        },
        201,
      ),
    );

    const res = await client.buildCredential({
      schema: "education",
      issuer: "did:key:z123",
      publicKey: "pk-id",
      credentialSubject: { name: "Alice" },
      validFrom: "2024-01-01T00:00:00Z",
      revocationRegistryUrl: "https://example.com/rev",
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/build");
    expect(opts.headers["Authorization"]).toBe("Bearer test-token");
    expect(res.sessionId).toBe("abc-123");
  });

  it("sends package request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({
        credential: { "@context": [] },
        formats: { jsonld: { "@context": [] } },
      }),
    );

    const res = await client.packageCredential({
      sessionId: "abc-123",
      signature: "c2lnbmF0dXJl",
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/package");
    expect(res.credential).toBeDefined();
  });

  it("sends verify request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({
        status: "VALID",
        checks: {
          signature: { passed: true },
          expiry: { passed: true },
          revocation: { passed: true },
        },
      }),
    );

    const res = await client.verifyCredential({ "@context": [], type: ["VerifiableCredential"] });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/verify");
    expect(res.status).toBe("VALID");
  });

  it("throws on API error responses", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({ error: { code: "VALIDATION_ERROR", message: "Schema not found" } }, 400),
    );

    await expect(client.verifyCredential({})).rejects.toThrow("Schema not found");
  });

  it("omits Authorization header when no token provided", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(jsonResponse({ status: "VALID", checks: {} }));

    await client.verifyCredential({});

    const [, opts] = mockFetch.mock.calls[0];
    expect(opts.headers["Authorization"]).toBeUndefined();
  });
});
