/**
 * Tests for `createDeDiDIDWebFallback`.
 *
 * The fallback is small (one method's worth of surface), so the tests
 * focus on the contract that `DIDWebResolver` relies on:
 *   - Returns a well-formed `DIDResolutionResult` when DeDi has the DID.
 *   - Returns `null` (not throws) for every failure mode the DeDi client
 *     can surface, so the resolver re-raises the original HTTPS error
 *     instead of overwriting it with a less actionable DeDi message.
 *   - Hands `record.document` through verbatim — the DID-document
 *     contract is enforced by downstream verification, not here.
 */

import { describe, it, expect, vi } from "vitest";

import type { DeDiClient } from "../adapter/client.js";
import type { DIDRecord } from "../adapter/types.js";
import { createDeDiDIDWebFallback } from "../adapter/did-web-fallback.js";

function makeMockClient(impl: { resolveDID?: (did: string) => Promise<DIDRecord> }): DeDiClient {
  // Cast to the minimal surface we need; the resolver only ever calls
  // resolveDID. Building a real client would drag the api-client mock
  // in for no incremental coverage.
  return {
    resolveDID:
      impl.resolveDID ??
      ((): Promise<DIDRecord> => {
        throw new Error("not implemented");
      }),
  } as unknown as DeDiClient;
}

describe("createDeDiDIDWebFallback", () => {
  it("returns a DIDResolutionResult when DeDi has the DID", async () => {
    const did = "did:web:example.com";
    const document = {
      "@context": "https://www.w3.org/ns/did/v1",
      id: did,
      verificationMethod: [
        {
          id: `${did}#key-0`,
          type: "JsonWebKey",
          controller: did,
          publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
        },
      ],
      assertionMethod: [`${did}#key-0`],
    };
    const client = makeMockClient({
      resolveDID: vi.fn().mockResolvedValue({
        did,
        document,
        keyStatus: "current",
      }),
    });

    const fallback = createDeDiDIDWebFallback(client);
    const result = await fallback(did);

    expect(result).not.toBeNull();
    expect(result!.didDocument).toEqual(document);
    expect(result!.didResolutionMetadata).toEqual({ contentType: "application/did+json" });
    // `resolvedAt` is wall-clock at resolve time (the DIDRecord no longer
    // carries one); assert shape, not value.
    expect(result!.didDocumentMetadata).toHaveProperty("resolvedAt");
    expect(typeof result!.didDocumentMetadata.resolvedAt).toBe("string");
  });

  it("returns null when DeDi has no record for the DID", async () => {
    const client = makeMockClient({
      resolveDID: vi.fn().mockRejectedValue(new Error("Record not found")),
    });

    const fallback = createDeDiDIDWebFallback(client);
    const result = await fallback("did:web:missing.example.com");

    expect(result).toBeNull();
  });

  it("returns null on any DeDi-side error (network, 5xx, malformed shape)", async () => {
    // The fallback must swallow these. The DIDWebResolver re-raises the
    // original HTTPS error when the fallback returns null, which is
    // almost always more actionable than a generic "DeDi failed" message.
    const errors = [
      new Error("ECONNREFUSED"),
      new Error("502 Bad Gateway"),
      new Error("Response shape invalid"),
      new Error("Circuit breaker open"),
    ];
    for (const err of errors) {
      const client = makeMockClient({
        resolveDID: vi.fn().mockRejectedValue(err),
      });
      const fallback = createDeDiDIDWebFallback(client);
      const result = await fallback("did:web:example.com");
      expect(result).toBeNull();
    }
  });

  it("returns null when DeDi returns a record with a non-object document", async () => {
    // Documents come over the wire as `unknown`. The DeDi adapter
    // sanity-checks the outer record shape, but the inner `document`
    // field is opaque — guard against non-objects before claiming
    // we have a DIDDocument.
    const client = makeMockClient({
      resolveDID: vi.fn().mockResolvedValue({
        did: "did:web:malformed.example.com",
        document: "not an object",
        keyStatus: "current",
      } as unknown as DIDRecord),
    });

    const fallback = createDeDiDIDWebFallback(client);
    const result = await fallback("did:web:malformed.example.com");

    expect(result).toBeNull();
  });

  it("returns null when DeDi returns a record with a null document", async () => {
    const client = makeMockClient({
      resolveDID: vi.fn().mockResolvedValue({
        did: "did:web:malformed.example.com",
        document: undefined,
        keyStatus: "current",
      } as unknown as DIDRecord),
    });

    const fallback = createDeDiDIDWebFallback(client);
    const result = await fallback("did:web:malformed.example.com");

    expect(result).toBeNull();
  });

  it("forwards the DID verbatim to resolveDID (no normalization)", async () => {
    // The DeDi adapter handles record-name encoding internally; the
    // fallback just passes the input DID through. Pin that so a future
    // accidental DID normalization here doesn't desync from the
    // adapter's encoding.
    const seen: string[] = [];
    const client = makeMockClient({
      resolveDID: vi.fn().mockImplementation(async (did: string) => {
        seen.push(did);
        throw new Error("not found");
      }),
    });

    const fallback = createDeDiDIDWebFallback(client);
    const did = "did:web:edge-case.example.com%3A8443:path:segments";
    await fallback(did);

    expect(seen).toEqual([did]);
  });
});
