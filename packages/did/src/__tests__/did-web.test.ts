import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  encodeDidWeb,
  didWebVerificationMethodId,
  didWebToUrl,
  generateDidWebDocument,
  generateDidWebDocumentMultiKey,
  DIDWebResolver,
  verifyDidWeb,
} from "../did-web.js";
import { DIDResolutionError } from "@opencred/shared";
import type { JWK } from "../types.js";

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

  // Single-arg form: the whole `OPENCRED_ISSUER_DOMAIN` is passed as one
  // string. Path-separator colons must be preserved (regression for #708).
  it("should preserve path-separator colons in a combined identifier", () => {
    expect(encodeDidWeb("trade.clickpower.in:ies:publicfiles")).toBe(
      "did:web:trade.clickpower.in:ies:publicfiles",
    );
  });

  it("should not encode a non-numeric first path segment as a port", () => {
    expect(encodeDidWeb("did.cord.network:76EU7h2qxfauoLdvRWqSi5jxci13MTTjQ3mTzCrC5QSCAzwWq78Rid")).toBe(
      "did:web:did.cord.network:76EU7h2qxfauoLdvRWqSi5jxci13MTTjQ3mTzCrC5QSCAzwWq78Rid",
    );
  });

  it("should encode a numeric port but keep trailing path segments in a combined identifier", () => {
    expect(encodeDidWeb("example.com:8080:users:alice")).toBe(
      "did:web:example.com%3A8080:users:alice",
    );
  });

  it("should pass through an already percent-encoded port", () => {
    expect(encodeDidWeb("example.com%3A3000:path")).toBe("did:web:example.com%3A3000:path");
  });
});

// encodeDidWeb and didWebToUrl must be inverses: a DID built from a domain
// must resolve back to the URL where that domain serves its did.json (#708).
describe("encodeDidWeb <-> didWebToUrl round-trip", () => {
  it.each([
    ["example.com", "https://example.com/.well-known/did.json"],
    ["trade.clickpower.in:ies:publicfiles", "https://trade.clickpower.in/ies/publicfiles/did.json"],
    ["example.com:3000", "https://example.com:3000/.well-known/did.json"],
    ["example.com:8080:users:alice", "https://example.com:8080/users/alice/did.json"],
    ["example.com%3A3000:path", "https://example.com:3000/path/did.json"],
  ])("round-trips %s", (domain, expectedUrl) => {
    expect(didWebToUrl(encodeDidWeb(domain))).toBe(expectedUrl);
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

  it("delegates to the multi-key generator (single #key-0 entry)", () => {
    // The single-key wrapper is now a thin shim over the multi-key
    // generator with a conventional `${did}#key-0` fragment. Pin that the
    // output is byte-for-byte the same as calling the multi-key generator
    // directly with that one key.
    const did = "did:web:example.com";
    const single = generateDidWebDocument(did, sampleJwk);
    const multi = generateDidWebDocumentMultiKey(did, [
      { id: `${did}#key-0`, publicKeyJwk: sampleJwk },
    ]);
    expect(single).toEqual(multi);
  });
});

describe("generateDidWebDocumentMultiKey", () => {
  const did = "did:web:example.com";
  const secondJwk: JWK = {
    kty: "EC",
    crv: "P-256",
    x: "different-x-coordinate-value-for-second-key",
    y: "different-y-coordinate-value-for-second-key",
  };

  it("emits a single verificationMethod for a one-key set", () => {
    const doc = generateDidWebDocumentMultiKey(did, [
      { id: `${did}#key-0`, publicKeyJwk: sampleJwk },
    ]);

    expect(doc["@context"]).toEqual([
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ]);
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod).toHaveLength(1);

    const vm = doc.verificationMethod![0];
    expect(vm.id).toBe(`${did}#key-0`);
    expect(vm.type).toBe("JsonWebKey");
    expect(vm.controller).toBe(did);
    expect(vm.publicKeyJwk).toEqual(sampleJwk);
  });

  it("emits one verificationMethod per key for an N-key set", () => {
    const keys = [
      { id: `${did}#key-0`, publicKeyJwk: sampleJwk },
      { id: `${did}#key-1`, publicKeyJwk: secondJwk },
    ];
    const doc = generateDidWebDocumentMultiKey(did, keys);

    expect(doc.verificationMethod).toHaveLength(2);
    expect(doc.verificationMethod![0]).toEqual({
      id: `${did}#key-0`,
      type: "JsonWebKey",
      controller: did,
      publicKeyJwk: sampleJwk,
    });
    expect(doc.verificationMethod![1]).toEqual({
      id: `${did}#key-1`,
      type: "JsonWebKey",
      controller: did,
      publicKeyJwk: secondJwk,
    });
  });

  it("lists every key id in all four verification relationships", () => {
    const keys = [
      { id: `${did}#key-0`, publicKeyJwk: sampleJwk },
      { id: `${did}#key-1`, publicKeyJwk: secondJwk },
    ];
    const ids = keys.map((k) => k.id);
    const doc = generateDidWebDocumentMultiKey(did, keys);

    expect(doc.authentication).toEqual(ids);
    expect(doc.assertionMethod).toEqual(ids);
    expect(doc.capabilityInvocation).toEqual(ids);
    expect(doc.capabilityDelegation).toEqual(ids);
  });

  it("accepts cross-method key ids (e.g. did:key fragments) verbatim", () => {
    const keyId = "did:key:z6MkExample#z6MkExample";
    const doc = generateDidWebDocumentMultiKey(did, [{ id: keyId, publicKeyJwk: sampleJwk }]);

    expect(doc.verificationMethod![0].id).toBe(keyId);
    // controller is always the document DID, even for a cross-method key id.
    expect(doc.verificationMethod![0].controller).toBe(did);
    expect(doc.assertionMethod).toEqual([keyId]);
  });

  it("throws DIDResolutionError when the key set is empty", () => {
    expect(() => generateDidWebDocumentMultiKey(did, [])).toThrow(DIDResolutionError);
  });

  it("throws DIDResolutionError when keys is null/undefined", () => {
    expect(() => generateDidWebDocumentMultiKey(did, undefined as unknown as never)).toThrow(
      DIDResolutionError,
    );
  });
});

describe("DIDWebResolver", () => {
  const resolver = new DIDWebResolver();

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
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
    const dns = await import("node:dns");
    vi.spyOn(dns.promises, "resolve4").mockResolvedValue(["127.0.0.1"]);

    await expect(resolver.resolve("did:web:evil.example.com")).rejects.toThrow("SSRF protection");
  });

  it("should reject when DNS resolution fails", async () => {
    const dns = await import("node:dns");
    vi.spyOn(dns.promises, "resolve4").mockRejectedValue(new Error("ENOTFOUND"));

    await expect(resolver.resolve("did:web:nonexistent.example.com")).rejects.toThrow(
      "Failed to resolve hostname",
    );
  });

  it("should resolve a valid did:web with mocked fetch", async () => {
    const did = "did:web:example.com";
    const expectedDoc = generateDidWebDocument(did, sampleJwk);

    const dns = await import("node:dns");
    vi.spyOn(dns.promises, "resolve4").mockResolvedValue(["93.184.216.34"]);

    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue(expectedDoc),
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

    const result = await resolver.resolve(did);

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);
    expect(result.didDocument!.verificationMethod).toHaveLength(1);

    const vm = result.didDocument!.verificationMethod![0];
    expect(vm.type).toBe("JsonWebKey");
    expect(vm.publicKeyJwk).toEqual(sampleJwk);

    expect(result.didResolutionMetadata.contentType).toBe("application/did+ld+json");
    expect(result.didDocumentMetadata).toEqual({});

    // Verify fetch was called with correct URL and options
    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/.well-known/did.json",
      expect.objectContaining({
        redirect: "error",
        headers: { Accept: "application/did+ld+json, application/json" },
      }),
    );
  });

  it("should reject when HTTP response is not ok", async () => {
    const dns = await import("node:dns");
    vi.spyOn(dns.promises, "resolve4").mockResolvedValue(["93.184.216.34"]);

    const mockResponse = {
      ok: false,
      status: 404,
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

    await expect(resolver.resolve("did:web:example.com")).rejects.toThrow("HTTP 404");
  });

  it("should reject when DID document ID does not match", async () => {
    const dns = await import("node:dns");
    vi.spyOn(dns.promises, "resolve4").mockResolvedValue(["93.184.216.34"]);

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
    const dns = await import("node:dns");
    vi.spyOn(dns.promises, "resolve4").mockResolvedValue(["93.184.216.34"]);

    const mockResponse = {
      ok: true,
      json: vi.fn().mockRejectedValue(new SyntaxError("Unexpected token")),
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

    await expect(resolver.resolve("did:web:example.com")).rejects.toThrow(
      "Failed to parse DID document",
    );
  });
});

describe("verifyDidWeb", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const did = "did:web:example.com";

  /**
   * Helper that wires DNS + fetch mocks for the happy path. We use
   * `await import("node:dns")` rather than `require(...)` to stay
   * compatible with the package's ESM module type — `require` is not
   * available at runtime here, and is also rejected by
   * `@typescript-eslint/no-require-imports` in CI.
   */
  async function mockSuccessfulFetch(
    doc: ReturnType<typeof generateDidWebDocument>,
  ): Promise<void> {
    const dns = await import("node:dns");
    // `DIDWebResolver.resolveViaHttps` does `Promise.allSettled([resolve4,
    // resolve6])`. We need to stub BOTH or the unstubbed call falls through
    // to real DNS in CI, the SSRF check runs against actual public IPs, and
    // `fetch` (also unstubbed in that path) hits the real network — making
    // the test environment-dependent and flaky.
    vi.spyOn(dns.promises, "resolve4").mockResolvedValue(["93.184.216.34"]);
    vi.spyOn(dns.promises, "resolve6").mockRejectedValue(new Error("no AAAA"));
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, json: vi.fn().mockResolvedValue(doc) }),
    );
  }

  it("returns accessible:true when the DID resolves and no key check is requested", async () => {
    await mockSuccessfulFetch(generateDidWebDocument(did, sampleJwk));

    const result = await verifyDidWeb(did);

    expect(result.accessible).toBe(true);
    expect(result.keyMatches).toBeUndefined();
    expect(result.didDocument?.id).toBe(did);
    expect(result.error).toBeUndefined();
  });

  it("returns accessible:true and keyMatches:true when the published key matches", async () => {
    await mockSuccessfulFetch(generateDidWebDocument(did, sampleJwk));

    const result = await verifyDidWeb(did, { expectedPublicKey: sampleJwk });

    expect(result.accessible).toBe(true);
    expect(result.keyMatches).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("returns keyMatches:false when the published key differs", async () => {
    await mockSuccessfulFetch(generateDidWebDocument(did, sampleJwk));
    const otherKey: JWK = { ...sampleJwk, x: "different-x-value" };

    const result = await verifyDidWeb(did, { expectedPublicKey: otherKey });

    expect(result.accessible).toBe(true);
    expect(result.keyMatches).toBe(false);
    expect(result.error).toMatch(/does not reference the expected public key/);
  });

  it("returns accessible:false with an error message when the fetch fails", async () => {
    const dns = await import("node:dns");
    // Reject BOTH DNS families so the SSRF guard doesn't fall through to a
    // real AAAA-only lookup in CI. See note in mockSuccessfulFetch.
    vi.spyOn(dns.promises, "resolve4").mockRejectedValue(new Error("ENOTFOUND"));
    vi.spyOn(dns.promises, "resolve6").mockRejectedValue(new Error("ENOTFOUND"));

    const result = await verifyDidWeb(did);

    expect(result.accessible).toBe(false);
    expect(result.error).toMatch(/Failed to resolve hostname/);
    expect(result.keyMatches).toBeUndefined();
    expect(result.didDocument).toBeUndefined();
  });

  it("does not crash and reports failure when the document has no verificationMethod", async () => {
    const dns = await import("node:dns");
    vi.spyOn(dns.promises, "resolve4").mockResolvedValue(["93.184.216.34"]);
    vi.spyOn(dns.promises, "resolve6").mockRejectedValue(new Error("no AAAA"));
    const docWithoutVm = { "@context": "https://www.w3.org/ns/did/v1", id: did };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, json: vi.fn().mockResolvedValue(docWithoutVm) }),
    );

    const result = await verifyDidWeb(did, { expectedPublicKey: sampleJwk });

    expect(result.accessible).toBe(true);
    expect(result.keyMatches).toBe(false);
  });
});
