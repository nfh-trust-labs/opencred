/**
 * Tier 3 #9 of nfh-trust-labs/opencred#446 — cache-header coverage.
 *
 * Verifies:
 *  - GET /schemas, GET /schemas/:id, GET /keys/resolve, POST /keys/resolve
 *    all emit a deterministic `ETag` and a public `Cache-Control` directive.
 *  - A conditional GET with a matching `If-None-Match` returns 304 with the
 *    body stripped and validators preserved.
 *  - `POST /credentials/verify` emits `Cache-Control: private, max-age=60`
 *    so caller-side caches can dedupe rapid re-verifications without a
 *    shared CDN latching onto a per-caller response.
 *  - The ETag is deterministic across runs (no wall-clock leakage) and
 *    public-by-construction (the ETag input never includes secrets, only
 *    the response body — which is itself public).
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { createTestApp, generateTestKey, type TestKeyPair } from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import { setDeDiClient, resetDeDiClient } from "../dedi-singleton.js";
import {
  computeETag,
  stableStringify,
  etagMatches,
  CACHE_PRESETS,
} from "../middleware/cache-control.js";
import type { Hono } from "hono";

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);
});

afterEach(() => {
  resetDeDiClient();
});

// ---------------------------------------------------------------------------
// Pure-helper coverage
// ---------------------------------------------------------------------------

describe("stableStringify", () => {
  it("emits the same string regardless of object key order", () => {
    const a = { x: 1, y: { b: 2, a: 1 } };
    const b = { y: { a: 1, b: 2 }, x: 1 };
    expect(stableStringify(a)).toBe(stableStringify(b));
  });

  it("preserves array order (semantically significant)", () => {
    expect(stableStringify([1, 2, 3])).toBe("[1,2,3]");
    expect(stableStringify([1, 2, 3])).not.toBe(stableStringify([3, 2, 1]));
  });

  it("handles null/undefined/primitives", () => {
    expect(stableStringify(null)).toBe("null");
    expect(stableStringify(42)).toBe("42");
    expect(stableStringify("hi")).toBe('"hi"');
  });
});

describe("computeETag", () => {
  it("is deterministic for identical bodies", () => {
    const body = { did: "did:web:example.org", document: { id: "abc" } };
    expect(computeETag(body)).toBe(computeETag(body));
  });

  it("returns the weak-validator form W/\"<hex>\"", () => {
    const tag = computeETag({ a: 1 });
    expect(tag).toMatch(/^W\/"[0-9a-f]{64}"$/);
  });

  it("produces different etags for different bodies", () => {
    expect(computeETag({ a: 1 })).not.toBe(computeETag({ a: 2 }));
  });

  it("is insensitive to key ordering (weak comparison)", () => {
    expect(computeETag({ a: 1, b: 2 })).toBe(computeETag({ b: 2, a: 1 }));
  });
});

describe("etagMatches", () => {
  it("accepts wildcard", () => {
    expect(etagMatches("*", 'W/"abc"')).toBe(true);
  });

  it("matches comma-separated lists", () => {
    expect(etagMatches('W/"x", W/"abc"', 'W/"abc"')).toBe(true);
  });

  it("strips the W/ prefix on either side", () => {
    expect(etagMatches('"abc"', 'W/"abc"')).toBe(true);
    expect(etagMatches('W/"abc"', '"abc"')).toBe(true);
  });

  it("returns false on a non-match", () => {
    expect(etagMatches('W/"x"', 'W/"y"')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GET /schemas — cache headers
// ---------------------------------------------------------------------------

describe("GET /schemas cache headers", () => {
  it("emits Cache-Control + ETag", async () => {
    const res = await app.request("/schemas");
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe(CACHE_PRESETS.schemaOrContext);
    expect(res.headers.get("ETag")).toMatch(/^W\/"[0-9a-f]{64}"$/);
    expect(res.headers.get("Vary")).toContain("category");
  });

  it("returns 304 on conditional GET with matching If-None-Match", async () => {
    const res1 = await app.request("/schemas");
    const etag = res1.headers.get("ETag");
    expect(etag).not.toBeNull();

    const res2 = await app.request("/schemas", {
      headers: { "If-None-Match": etag! },
    });
    expect(res2.status).toBe(304);
    // 304 must carry the validators so a CDN can refresh its freshness state.
    expect(res2.headers.get("ETag")).toBe(etag);
    expect(res2.headers.get("Cache-Control")).toBe(CACHE_PRESETS.schemaOrContext);
    // Body MUST be empty on 304.
    expect(await res2.text()).toBe("");
  });

  it("returns 200 (not 304) when If-None-Match does NOT match", async () => {
    const res = await app.request("/schemas", {
      headers: { "If-None-Match": 'W/"not-the-tag"' },
    });
    expect(res.status).toBe(200);
  });

  it("ETag is the same across two successive responses (deterministic)", async () => {
    const r1 = await app.request("/schemas");
    const r2 = await app.request("/schemas");
    expect(r1.headers.get("ETag")).toBe(r2.headers.get("ETag"));
  });
});

// ---------------------------------------------------------------------------
// GET /schemas/:id — cache headers
// ---------------------------------------------------------------------------

describe("GET /schemas/:id cache headers", () => {
  it("emits Cache-Control + ETag on a successful lookup", async () => {
    const res = await app.request("/schemas/functional-identity/v1");
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe(CACHE_PRESETS.schemaOrContext);
    expect(res.headers.get("ETag")).toMatch(/^W\/"[0-9a-f]{64}"$/);
  });

  it("returns 304 on conditional GET with matching If-None-Match", async () => {
    const r1 = await app.request("/schemas/functional-identity/v1");
    const etag = r1.headers.get("ETag")!;

    const r2 = await app.request("/schemas/functional-identity/v1", {
      headers: { "If-None-Match": etag },
    });
    expect(r2.status).toBe(304);
    expect(await r2.text()).toBe("");
  });

  it("does not add cache headers to 404 responses", async () => {
    const res = await app.request("/schemas/does-not-exist/v1");
    expect(res.status).toBe(404);
    expect(res.headers.get("ETag")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// /keys/resolve — cache headers (POST and GET)
// ---------------------------------------------------------------------------

const SAMPLE_DID_DOCUMENT = {
  "@context": "https://www.w3.org/ns/did/v1",
  id: "did:web:bootcamp.example.org",
  verificationMethod: [
    {
      id: "did:web:bootcamp.example.org#k1",
      type: "JsonWebKey2020",
      controller: "did:web:bootcamp.example.org",
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    },
  ],
};

describe("POST /keys/resolve cache headers", () => {
  it("emits Cache-Control + ETag when DeDi resolves successfully", async () => {
    const mockClient = {
      resolveDID: async (did: string) => ({
        did,
        document: SAMPLE_DID_DOCUMENT,
        keyStatus: "current" as const,
      }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:web:bootcamp.example.org" }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe(CACHE_PRESETS.didDocument);
    expect(res.headers.get("ETag")).toMatch(/^W\/"[0-9a-f]{64}"$/);
  });

  it("returns 304 on conditional POST with matching If-None-Match", async () => {
    const mockClient = {
      resolveDID: async (did: string) => ({
        did,
        document: SAMPLE_DID_DOCUMENT,
        keyStatus: "current" as const,
      }),
    } as never;
    setDeDiClient(mockClient);

    const r1 = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:web:bootcamp.example.org" }),
    });
    const etag = r1.headers.get("ETag")!;

    const r2 = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-None-Match": etag },
      body: JSON.stringify({ did: "did:web:bootcamp.example.org" }),
    });
    expect(r2.status).toBe(304);
    expect(await r2.text()).toBe("");
  });
});

describe("GET /keys/resolve", () => {
  it("returns the resolved DID record with cache headers", async () => {
    const mockClient = {
      resolveDID: async (did: string) => ({
        did,
        document: SAMPLE_DID_DOCUMENT,
        keyStatus: "current" as const,
      }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/resolve?did=did:web:bootcamp.example.org");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { did: string };
    expect(body.did).toBe("did:web:bootcamp.example.org");
    expect(res.headers.get("Cache-Control")).toBe(CACHE_PRESETS.didDocument);
    expect(res.headers.get("ETag")).toMatch(/^W\/"[0-9a-f]{64}"$/);
  });

  it("returns 400 when did query param is missing", async () => {
    const mockClient = { resolveDID: async () => ({}) } as never;
    setDeDiClient(mockClient);
    const res = await app.request("/v1/keys/resolve");
    expect(res.status).toBe(400);
  });

  it("returns 503 when DeDi is not configured", async () => {
    const res = await app.request("/v1/keys/resolve?did=did:web:bootcamp.example.org");
    expect(res.status).toBe(503);
  });

  it("returns 304 on conditional GET with matching If-None-Match", async () => {
    const mockClient = {
      resolveDID: async (did: string) => ({
        did,
        document: SAMPLE_DID_DOCUMENT,
        keyStatus: "current" as const,
      }),
    } as never;
    setDeDiClient(mockClient);

    const r1 = await app.request("/v1/keys/resolve?did=did:web:bootcamp.example.org");
    const etag = r1.headers.get("ETag")!;

    const r2 = await app.request("/v1/keys/resolve?did=did:web:bootcamp.example.org", {
      headers: { "If-None-Match": etag },
    });
    expect(r2.status).toBe(304);
  });
});

// ---------------------------------------------------------------------------
// POST /credentials/verify — private cache headers
// ---------------------------------------------------------------------------

describe("POST /credentials/verify cache headers", () => {
  it("sets Cache-Control: private, max-age=60 + Vary headers on a verify response", async () => {
    // We don't care about the verification verdict — only that the
    // cache headers are set on the response. A syntactically valid but
    // semantically broken credential takes us through the verifier and
    // returns a 200 with `valid: false`.
    const fakeCredential = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential"],
      issuer: "did:key:zUnknown",
      credentialSubject: { id: "did:example:subject" },
      validFrom: "2025-01-01T00:00:00Z",
      proof: { type: "JsonWebSignature2020", jwt: "header.body.signature" },
    };
    const res = await app.request("/v1/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: JSON.stringify(fakeCredential) }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe(CACHE_PRESETS.verifyPrivate);
    const vary = res.headers.get("Vary");
    expect(vary).toContain("Content-Type");
    expect(vary).toContain("Authorization");
  });
});
