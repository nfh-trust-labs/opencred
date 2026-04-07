import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("node:dns/promises", () => ({
  resolve4: vi.fn(),
  resolve6: vi.fn(),
}));

import {
  encodeDidWeb,
  didWebVerificationMethodId,
  didWebToUrl,
  generateDidWebDocument,
  DIDWebResolver,
} from "../did-web.js";
import { DIDResolutionError } from "@opencred/shared";
import { resolve4, resolve6 } from "node:dns/promises";
import type { JWK } from "../types.js";

const mockResolve4 = vi.mocked(resolve4);
const mockResolve6 = vi.mocked(resolve6);

const sampleJwk: JWK = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};

describe("encodeDidWeb", () => {
  it("should encode a bare domain", () => {
    expect(encodeDidWeb("example.com")).toBe("did:web:example.com");
  });

  it("should encode a domain with port by percent-encoding the colon", () => {
    expect(encodeDidWeb("example.com:3000")).toBe("did:web:example.com%3A3000");
  });

  it("should encode a domain with path segments", () => {
    expect(encodeDidWeb("example.com", ["path", "to"])).toBe("did:web:example.com:path:to");
  });

  it("should encode a domain with port and path segments", () => {
    expect(encodeDidWeb("example.com:8080", ["users", "alice"])).toBe(
      "did:web:example.com%3A8080:users:alice",
    );
  });

  it("should handle empty path array", () => {
    expect(encodeDidWeb("example.com", [])).toBe("did:web:example.com");
  });
});

describe("didWebVerificationMethodId", () => {
  it("should append #key-0 to the DID", () => {
    const did = "did:web:example.com";
    expect(didWebVerificationMethodId(did)).toBe("did:web:example.com#key-0");
  });
});

describe("didWebToUrl", () => {
  it("should convert a bare domain to .well-known URL", () => {
    expect(didWebToUrl("did:web:example.com")).toBe("https://example.com/.well-known/did.json");
  });

  it("should convert a domain with subpath to path-based URL", () => {
    expect(didWebToUrl("did:web:example.com:path:to")).toBe("https://example.com/path/to/did.json");
  });

  it("should decode percent-encoded port numbers", () => {
    expect(didWebToUrl("did:web:example.com%3A3000")).toBe(
      "https://example.com:3000/.well-known/did.json",
    );
  });

  it("should handle port with path segments", () => {
    expect(didWebToUrl("did:web:example.com%3A8080:users:alice")).toBe(
      "https://example.com:8080/users/alice/did.json",
    );
  });

  it("should throw on invalid DID format", () => {
    expect(() => didWebToUrl("not-a-did")).toThrow(DIDResolutionError);
  });

  it("should throw on non-web DID method", () => {
    expect(() => didWebToUrl("did:key:z1234")).toThrow(DIDResolutionError);
  });

  it("should throw on null input", () => {
    expect(() => didWebToUrl(null as unknown as string)).toThrow(DIDResolutionError);
  });
});

describe("generateDidWebDocument", () => {
  it("should produce a valid DID document structure", () => {
    const did = "did:web:example.com";
    const doc = generateDidWebDocument(did, sampleJwk);

    expect(doc["@context"]).toEqual([
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ]);
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod).toHaveLength(1);

    const vm = doc.verificationMethod![0];
    expect(vm.id).toBe("did:web:example.com#key-0");
    expect(vm.type).toBe("JsonWebKey");
    expect(vm.controller).toBe(did);
    expect(vm.publicKeyJwk).toEqual(sampleJwk);
  });

  it("should include all verification relationships", () => {
    const did = "did:web:example.com";
    const doc = generateDidWebDocument(did, sampleJwk);

    const expectedId = "did:web:example.com#key-0";
    expect(doc.authentication).toEqual([expectedId]);
    expect(doc.assertionMethod).toEqual([expectedId]);
    expect(doc.capabilityInvocation).toEqual([expectedId]);
    expect(doc.capabilityDelegation).toEqual([expectedId]);
  });
});

describe("DIDWebResolver", () => {
  const resolver = new DIDWebResolver();

  /**
   * Mock both resolve4 and resolve6 in one shot. Defaults to rejecting both
   * (so any test that forgets to set them up gets a clean failure rather than
   * leaking real DNS calls).
   */
  function mockDns(opts: {
    v4?: string[] | Error;
    v6?: string[] | Error;
  }): void {
    const v4 = opts.v4 ?? new Error("ENODATA");
    const v6 = opts.v6 ?? new Error("ENODATA");
    if (v4 instanceof Error) {
      mockResolve4.mockRejectedValue(v4);
    } else {
      mockResolve4.mockResolvedValue(v4);
    }
    if (v6 instanceof Error) {
      mockResolve6.mockRejectedValue(v6);
    } else {
      mockResolve6.mockResolvedValue(v6);
    }
  }

  beforeEach(() => {
    mockResolve4.mockReset();
    mockResolve6.mockReset();
    mockResolve4.mockRejectedValue(new Error("ENODATA"));
    mockResolve6.mockRejectedValue(new Error("ENODATA"));
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    mockResolve4.mockReset();
    mockResolve6.mockReset();
    vi.unstubAllGlobals();
  });

  it("should reject a non-string DID", async () => {
    await expect(resolver.resolve(null as unknown as string)).rejects.toThrow(DIDResolutionError);
    await expect(resolver.resolve(undefined as unknown as string)).rejects.toThrow(
      DIDResolutionError,
    );
  });

  it("should reject a malformed DID", async () => {
    await expect(resolver.resolve("not-a-did")).rejects.toThrow(DIDResolutionError);
  });

  it("should reject a non-web DID method", async () => {
    await expect(resolver.resolve("did:key:z1234")).rejects.toThrow("Unsupported DID method: key");
  });

  it("should reject when hostname resolves to a private IP (SSRF protection)", async () => {
    mockDns({ v4: ["127.0.0.1"] });

    await expect(resolver.resolve("did:web:evil.example.com")).rejects.toThrow(
      "SSRF protection",
    );
  });

  it("should reject when ANY resolved IP is private (mixed records)", async () => {
    // First record is public, second is loopback. The buggy "single-IP check
    // then re-resolve" pattern would let this through; the fixed code rejects
    // because at least one resolved address is private.
    mockDns({ v4: ["93.184.216.34", "127.0.0.1"] });

    await expect(resolver.resolve("did:web:evil.example.com")).rejects.toThrow("SSRF protection");
  });

  it("should reject when DNS resolution fails", async () => {
    mockDns({});

    await expect(resolver.resolve("did:web:nonexistent.example.com")).rejects.toThrow(
      "Failed to resolve hostname",
    );
  });

  it("should pin the resolved IP into the fetch URL and set the Host header (DNS rebinding defence)", async () => {
    const did = "did:web:example.com";
    const expectedDoc = generateDidWebDocument(did, sampleJwk);

    mockDns({ v4: ["93.184.216.34"] });

    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue(expectedDoc),
    };
    const fetchSpy = vi.fn().mockResolvedValue(mockResponse);
    vi.stubGlobal("fetch", fetchSpy);

    const result = await resolver.resolve(did);

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);

    // Critical assertion: the URL fetch was called with must contain the
    // resolved IP, NOT the original hostname. Otherwise fetch would re-resolve.
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const calledUrl = fetchSpy.mock.calls[0][0] as string;
    expect(calledUrl).toBe("https://93.184.216.34/.well-known/did.json");
    expect(calledUrl).not.toContain("example.com");

    // The Host header carries the original hostname so the server's
    // virtual-host routing still works.
    const calledOptions = fetchSpy.mock.calls[0][1] as {
      headers: Record<string, string>;
      redirect: string;
    };
    expect(calledOptions.headers.Host).toBe("example.com");
    expect(calledOptions.headers.Accept).toBe("application/did+ld+json, application/json");
    expect(calledOptions.redirect).toBe("error");
  });

  it("should NOT re-resolve hostname between SSRF check and fetch (DNS rebinding TOCTOU defence)", async () => {
    // Simulate a DNS rebinding attacker: the first resolve4 call (used for
    // the SSRF check) returns a public IP. A subsequent call (which would
    // happen if fetch re-resolved the hostname) returns a private IP. The
    // fixed code never makes that subsequent call because it pins the IP.
    const did = "did:web:rebinding.example.com";
    const expectedDoc = generateDidWebDocument(did, sampleJwk);

    mockResolve4
      .mockResolvedValueOnce(["93.184.216.34"]) // First call: public
      .mockResolvedValueOnce(["127.0.0.1"]); // Hypothetical re-resolve: loopback
    // resolve6 is left at its default (rejecting with ENODATA).

    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue(expectedDoc),
    };
    const fetchSpy = vi.fn().mockResolvedValue(mockResponse);
    vi.stubGlobal("fetch", fetchSpy);

    await resolver.resolve(did);

    // The defining assertion: resolve4 was called exactly ONCE. If the code
    // re-resolved the hostname during fetch, the count would be 2 and the
    // second (rebound) IP would be used.
    expect(mockResolve4).toHaveBeenCalledTimes(1);

    // And the URL fetch was called with is the FIRST (pinned) IP.
    const calledUrl = fetchSpy.mock.calls[0][0] as string;
    expect(calledUrl).toContain("93.184.216.34");
    expect(calledUrl).not.toContain("127.0.0.1");
    expect(calledUrl).not.toContain("rebinding.example.com");
  });

  it("should reject when HTTP response is not ok", async () => {
    mockDns({ v4: ["93.184.216.34"] });

    const mockResponse = {
      ok: false,
      status: 404,
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

    await expect(resolver.resolve("did:web:example.com")).rejects.toThrow("HTTP 404");
  });

  it("should reject when DID document ID does not match", async () => {
    mockDns({ v4: ["93.184.216.34"] });

    const wrongDoc = generateDidWebDocument("did:web:wrong.com", sampleJwk);
    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue(wrongDoc),
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

    await expect(resolver.resolve("did:web:example.com")).rejects.toThrow(
      "DID document ID mismatch",
    );
  });

  it("should reject when response is not valid JSON", async () => {
    mockDns({ v4: ["93.184.216.34"] });

    const mockResponse = {
      ok: true,
      json: vi.fn().mockRejectedValue(new SyntaxError("Unexpected token")),
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

    await expect(resolver.resolve("did:web:example.com")).rejects.toThrow(
      "Failed to parse DID document",
    );
  });

  it("should pin an IPv6 address in brackets in the fetch URL", async () => {
    const did = "did:web:ipv6only.example.com";
    const expectedDoc = generateDidWebDocument(did, sampleJwk);

    mockDns({
      v4: new Error("ENODATA"),
      v6: ["2606:2800:220:1:248:1893:25c8:1946"],
    });

    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue(expectedDoc),
    };
    const fetchSpy = vi.fn().mockResolvedValue(mockResponse);
    vi.stubGlobal("fetch", fetchSpy);

    await resolver.resolve(did);

    const calledUrl = fetchSpy.mock.calls[0][0] as string;
    expect(calledUrl).toContain("[2606:2800:220:1:248:1893:25c8:1946]");
    expect(calledUrl).not.toContain("ipv6only.example.com");
  });
});
