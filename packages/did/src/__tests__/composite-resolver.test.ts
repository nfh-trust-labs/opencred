import { describe, it, expect, vi } from "vitest";
import { CompositeDIDResolver } from "../composite-resolver.js";
import { DIDResolutionError } from "@opencred/shared";
import type { DIDResolver } from "../resolver.js";
import type { DIDResolutionResult } from "../types.js";

function createMockResolver(method: string): DIDResolver {
  return {
    resolve: vi.fn().mockResolvedValue({
      didDocument: { "@context": "https://www.w3.org/ns/did/v1", id: `did:${method}:test` },
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {},
    } satisfies DIDResolutionResult),
  };
}

describe("CompositeDIDResolver", () => {
  it("should route to the correct sub-resolver by method", async () => {
    const keyResolver = createMockResolver("key");
    const jwkResolver = createMockResolver("jwk");
    const webResolver = createMockResolver("web");

    const composite = new CompositeDIDResolver(
      new Map([
        ["key", keyResolver],
        ["jwk", jwkResolver],
        ["web", webResolver],
      ]),
    );

    await composite.resolve("did:key:z1234");
    expect(keyResolver.resolve).toHaveBeenCalledWith("did:key:z1234");
    expect(jwkResolver.resolve).not.toHaveBeenCalled();
    expect(webResolver.resolve).not.toHaveBeenCalled();
  });

  it("should route did:web to the web resolver", async () => {
    const webResolver = createMockResolver("web");

    const composite = new CompositeDIDResolver(new Map([["web", webResolver]]));

    await composite.resolve("did:web:example.com");
    expect(webResolver.resolve).toHaveBeenCalledWith("did:web:example.com");
  });

  it("should return the result from the sub-resolver", async () => {
    const keyResolver = createMockResolver("key");
    const composite = new CompositeDIDResolver(new Map([["key", keyResolver]]));

    const result = await composite.resolve("did:key:z1234");
    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe("did:key:test");
  });

  it("should throw DIDResolutionError for unknown DID method", async () => {
    const composite = new CompositeDIDResolver(new Map([["key", createMockResolver("key")]]));

    await expect(composite.resolve("did:unknown:test")).rejects.toThrow(DIDResolutionError);
    await expect(composite.resolve("did:unknown:test")).rejects.toThrow(
      "No resolver registered for DID method: unknown",
    );
  });

  it("should throw on empty string DID", async () => {
    const composite = new CompositeDIDResolver(new Map());
    await expect(composite.resolve("")).rejects.toThrow(DIDResolutionError);
  });

  it("should throw on null/undefined DID", async () => {
    const composite = new CompositeDIDResolver(new Map());
    await expect(composite.resolve(null as unknown as string)).rejects.toThrow(DIDResolutionError);
    await expect(composite.resolve(undefined as unknown as string)).rejects.toThrow(
      DIDResolutionError,
    );
  });

  it("should throw on malformed DID (missing parts)", async () => {
    const composite = new CompositeDIDResolver(new Map());
    await expect(composite.resolve("did:key")).rejects.toThrow(DIDResolutionError);
    await expect(composite.resolve("notadid")).rejects.toThrow(DIDResolutionError);
  });

  it("should propagate errors from sub-resolvers", async () => {
    const failingResolver: DIDResolver = {
      resolve: vi.fn().mockRejectedValue(new DIDResolutionError("sub-resolver failed")),
    };

    const composite = new CompositeDIDResolver(new Map([["key", failingResolver]]));

    await expect(composite.resolve("did:key:z1234")).rejects.toThrow("sub-resolver failed");
  });
});
