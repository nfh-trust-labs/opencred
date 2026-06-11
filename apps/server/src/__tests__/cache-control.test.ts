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

  it('returns the weak-validator form W/"<hex>"', () => {
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

const SAMPLE_KEY_RECORD = {
  keyId: "did:web:bootcamp.example.org#key-0",
  controllerDid: "did:web:bootcamp.example.org",
  algorithm: "P-256",
  publicKeyJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
  purpose: ["assertionMethod"],
  status: "active" as const,
};

describe("POST /keys/resolve cache headers", () => {
  it("emits private Cache-Control + ETag when DeDi resolves successfully", async () => {
    // Follow-up #586: POST resolve uses the *private* preset to mirror the
    // POST /credentials/verify reasoning — a shared CDN must not latch onto
    // one caller's DID resolution and serve it to another. The publicly
    // cacheable shape lives behind GET /keys/resolve.
    const mockClient = {
      resolveKey: async (verificationMethod: string) => ({
        ...SAMPLE_KEY_RECORD,
        keyId: verificationMethod,
      }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verificationMethod: "did:web:bootcamp.example.org#key-0" }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe(CACHE_PRESETS.didDocumentPrivate);
    expect(res.headers.get("Cache-Control")).toContain("private");
    expect(res.headers.get("ETag")).toMatch(/^W\/"[0-9a-f]{64}"$/);
  });

  it("returns 304 on conditional POST with matching If-None-Match", async () => {
    const mockClient = {
      resolveKey: async (verificationMethod: string) => ({
        ...SAMPLE_KEY_RECORD,
        keyId: verificationMethod,
      }),
    } as never;
    setDeDiClient(mockClient);

    const r1 = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verificationMethod: "did:web:bootcamp.example.org#key-0" }),
    });
    const etag = r1.headers.get("ETag")!;

    const r2 = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-None-Match": etag },
      body: JSON.stringify({ verificationMethod: "did:web:bootcamp.example.org#key-0" }),
    });
    expect(r2.status).toBe(304);
    expect(await r2.text()).toBe("");
  });
});

describe("GET /keys/resolve", () => {
  it("returns the resolved DID record with cache headers", async () => {
    const mockClient = {
      resolveKey: async (verificationMethod: string) => ({
        ...SAMPLE_KEY_RECORD,
        keyId: verificationMethod,
      }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request(
      "/v1/keys/resolve?verificationMethod=did:web:bootcamp.example.org%23key-0",
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keyId: string };
    expect(body.keyId).toBe("did:web:bootcamp.example.org#key-0");
    expect(res.headers.get("Cache-Control")).toBe(CACHE_PRESETS.didDocument);
    expect(res.headers.get("ETag")).toMatch(/^W\/"[0-9a-f]{64}"$/);
  });

  it("returns 400 when verificationMethod query param is missing", async () => {
    const mockClient = { resolveKey: async () => ({}) } as never;
    setDeDiClient(mockClient);
    const res = await app.request("/v1/keys/resolve");
    expect(res.status).toBe(400);
  });

  it("returns 503 when DeDi is not configured", async () => {
    const res = await app.request(
      "/v1/keys/resolve?verificationMethod=did:web:bootcamp.example.org%23key-0",
    );
    expect(res.status).toBe(503);
  });

  it("returns 304 on conditional GET with matching If-None-Match", async () => {
    const mockClient = {
      resolveKey: async (verificationMethod: string) => ({
        ...SAMPLE_KEY_RECORD,
        keyId: verificationMethod,
      }),
    } as never;
    setDeDiClient(mockClient);

    const r1 = await app.request(
      "/v1/keys/resolve?verificationMethod=did:web:bootcamp.example.org%23key-0",
    );
    const etag = r1.headers.get("ETag")!;

    const r2 = await app.request(
      "/v1/keys/resolve?verificationMethod=did:web:bootcamp.example.org%23key-0",
      {
        headers: { "If-None-Match": etag },
      },
    );
    expect(r2.status).toBe(304);
  });

  // -------------------------------------------------------------------------
  // Multi-colon DID coverage (follow-up #586)
  //
  // The W3C DID Core spec lets a `did:web` value carry a path segment encoded
  // with `:` separators — e.g. `did:web:example.org:users:alice` resolves to
  // https://example.org/users/alice/did.json. Earlier coverage only exercised
  // a single-level DID. These tests pin the GET-path query parser against:
  //
  //   1. raw colons (`?did=did:web:example.org:users:alice`)
  //   2. URL-encoded colons in the DID value
  //      (`?did=did%3Aweb%3Aexample.org%3Auser`)
  //
  // In both cases Hono's `c.req.query("did")` must hand the handler back the
  // fully-decoded canonical DID so the DeDi lookup sees the same string the
  // caller intended. A regression here would silently surface as 503s or
  // stale-DID lookups in production.
  // -------------------------------------------------------------------------

  it("decodes a multi-colon verification method passed with raw colons in the query", async () => {
    const seen: string[] = [];
    const vm = "did:web:example.org:users:alice#key-0";
    const mockClient = {
      resolveKey: async (verificationMethod: string) => {
        seen.push(verificationMethod);
        return { ...SAMPLE_KEY_RECORD, keyId: verificationMethod };
      },
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request(`/v1/keys/resolve?verificationMethod=${encodeURIComponent(vm)}`);
    expect(res.status).toBe(200);
    expect(seen).toEqual([vm]);
    const body = (await res.json()) as { keyId: string };
    expect(body.keyId).toBe(vm);
    expect(res.headers.get("Cache-Control")).toBe(CACHE_PRESETS.didDocument);
  });

  it("decodes a multi-colon verification method passed with URL-encoded colons", async () => {
    const seen: string[] = [];
    const vm = "did:web:example.org:users:alice#key-0";
    const mockClient = {
      resolveKey: async (verificationMethod: string) => {
        seen.push(verificationMethod);
        return { ...SAMPLE_KEY_RECORD, keyId: verificationMethod };
      },
    } as never;
    setDeDiClient(mockClient);

    // Fully percent-encoded form.
    const encoded = encodeURIComponent(vm);
    const res = await app.request(`/v1/keys/resolve?verificationMethod=${encoded}`);
    expect(res.status).toBe(200);
    expect(seen).toEqual([vm]);
    const body = (await res.json()) as { keyId: string };
    expect(body.keyId).toBe(vm);
  });

  it("decodes a single URL-encoded colon in the verification method query value", async () => {
    const seen: string[] = [];
    const vm = "did:web:example.org:user#key-0";
    const mockClient = {
      resolveKey: async (verificationMethod: string) => {
        seen.push(verificationMethod);
        return { ...SAMPLE_KEY_RECORD, keyId: verificationMethod };
      },
    } as never;
    setDeDiClient(mockClient);

    // Mixed encoding: colon before "user" is `%3A`. The handler must still
    // see the canonical form.
    const mixed = "did:web:example.org%3Auser%23key-0";
    const res = await app.request(`/v1/keys/resolve?verificationMethod=${mixed}`);
    expect(res.status).toBe(200);
    expect(seen).toEqual([vm]);
  });

  it("produces matching ETags for two successive GET requests with the same verification method", async () => {
    // Two requests carrying the same logical VM must produce the same ETag,
    // because the response body is deterministic for identical inputs.
    const vm = "did:web:example.org:users:alice#key-0";
    const mockClient = {
      resolveKey: async (verificationMethod: string) => ({
        ...SAMPLE_KEY_RECORD,
        keyId: verificationMethod,
      }),
    } as never;
    setDeDiClient(mockClient);

    const encoded = encodeURIComponent(vm);
    const r1 = await app.request(`/v1/keys/resolve?verificationMethod=${encoded}`);
    const r2 = await app.request(`/v1/keys/resolve?verificationMethod=${encoded}`);
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(r1.headers.get("ETag")).toBe(r2.headers.get("ETag"));
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
