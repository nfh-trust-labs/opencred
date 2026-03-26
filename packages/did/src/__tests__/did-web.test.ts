import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  encodeDidWeb,
  didWebVerificationMethodId,
  didWebToUrl,
  generateDidWebDocument,
  DIDWebResolver,
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
});

describe("didWebVerificationMethodId", () => {
  it("should append #key-0 to the DID", () => {
    const did = "did:web:example.com";
    expect(didWebVerificationMethodId(did)).toBe("did:web:example.com#key-0");
  });
});

describe("didWebToUrl", () => {
  it("should convert a bare domain to .well-known URL", () => {
    expect(didWebToUrl("did:web:example.com")).toBe(
      "https://example.com/.well-known/did.json",
    );
  });

  it("should convert a domain with subpath to path-based URL", () => {
    expect(didWebToUrl("did:web:example.com:path:to")).toBe(
      "https://example.com/path/to/did.json",
    );
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

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should reject a non-string DID", async () => {
    await expect(resolver.resolve(null as unknown as string)).rejects.toThrow(
      DIDResolutionError,
    );
    await expect(resolver.resolve(undefined as unknown as string)).rejects.toThrow(
      DIDResolutionError,
    );
  });

  it("should reject a malformed DID", async () => {
    await expect(resolver.resolve("not-a-did")).rejects.toThrow(DIDResolutionError);
  });

  it("should reject a non-web DID method", async () => {
    await expect(resolver.resolve("did:key:z1234")).rejects.toThrow(
      "Unsupported DID method: key",
    );
  });

  it("should reject when hostname resolves to a private IP (SSRF protection)", async () => {
    const dns = await import("node:dns");
    vi.spyOn(dns.promises, "resolve4").mockResolvedValue(["127.0.0.1"]);

    await expect(resolver.resolve("did:web:evil.example.com")).rejects.toThrow(
      "SSRF protection",
    );
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
