/**
 * Tier 3 #9 of nfh-trust-labs/opencred#446 — `OPENCRED_READ_ONLY` coverage.
 *
 * Verifies:
 *  - Read endpoints (verify, keys/resolve, schemas, health, revocation
 *    status / hash compute) continue to work in read-only mode.
 *  - Write endpoints (issue, batch, revoke, keys/publish, schemas/generate,
 *    dedi/namespace/ensure) return 405 with a `READ_ONLY_MODE` code.
 *  - Fail-closed: unknown POST paths under the denylisted prefixes are
 *    blocked too, so adding a new write route without updating
 *    `READ_OPERATIONS` doesn't silently expose a write surface on the
 *    read tier.
 *  - The `isAllowedUnderReadOnly` helper has unit coverage matching the
 *    decision tree in its docstring.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import {
  createTestApp,
  generateTestKey,
  VALID_ISSUE_REQUEST,
  type TestKeyPair,
} from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import { resetDeDiClient } from "../dedi-singleton.js";
import { isAllowedUnderReadOnly } from "../middleware/read-only.js";
import type { Hono } from "hono";

let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

afterEach(() => {
  delete process.env.OPENCRED_READ_ONLY;
  resetDeDiClient();
});

// ---------------------------------------------------------------------------
// Pure helper
// ---------------------------------------------------------------------------

describe("isAllowedUnderReadOnly", () => {
  it("allows GET / HEAD / OPTIONS unconditionally", () => {
    expect(isAllowedUnderReadOnly("GET", "/credentials/anything")).toBe(true);
    expect(isAllowedUnderReadOnly("HEAD", "/keys/publish")).toBe(true);
    expect(isAllowedUnderReadOnly("OPTIONS", "/credentials/issue")).toBe(true);
  });

  it("allows known POST reads", () => {
    expect(isAllowedUnderReadOnly("POST", "/credentials/verify")).toBe(true);
    expect(isAllowedUnderReadOnly("POST", "/v1/credentials/verify")).toBe(true);
    expect(isAllowedUnderReadOnly("POST", "/keys/resolve")).toBe(true);
    expect(isAllowedUnderReadOnly("POST", "/v1/keys/resolve")).toBe(true);
    expect(isAllowedUnderReadOnly("POST", "/credentials/revocation-status")).toBe(true);
    expect(isAllowedUnderReadOnly("POST", "/credentials/revocation-hash")).toBe(true);
    expect(isAllowedUnderReadOnly("POST", "/credentials/revocation-hash/batch")).toBe(true);
  });

  it("blocks known POST writes", () => {
    expect(isAllowedUnderReadOnly("POST", "/credentials/issue")).toBe(false);
    expect(isAllowedUnderReadOnly("POST", "/v1/credentials/issue")).toBe(false);
    expect(isAllowedUnderReadOnly("POST", "/credentials/batch")).toBe(false);
    expect(isAllowedUnderReadOnly("POST", "/credentials/revoke")).toBe(false);
    expect(isAllowedUnderReadOnly("POST", "/keys/publish")).toBe(false);
    expect(isAllowedUnderReadOnly("POST", "/v1/keys/publish")).toBe(false);
    expect(isAllowedUnderReadOnly("POST", "/schemas/generate")).toBe(false);
    expect(isAllowedUnderReadOnly("POST", "/dedi/namespace/ensure")).toBe(false);
  });

  it("fails closed for unknown POSTs under denylisted prefixes", () => {
    // If someone adds POST /credentials/reissue tomorrow without updating
    // the allowlist, read-only mode MUST block it.
    expect(isAllowedUnderReadOnly("POST", "/credentials/reissue")).toBe(false);
    expect(isAllowedUnderReadOnly("POST", "/v1/credentials/never-seen")).toBe(false);
    expect(isAllowedUnderReadOnly("POST", "/keys/anything-new")).toBe(false);
  });

  it("allows POSTs to non-write prefixes by default", () => {
    // /health, /metrics, and the rate-limit self-check are not under a
    // write prefix — POSTs there (none exist today, but they should be
    // allowed in principle) are not blocked.
    expect(isAllowedUnderReadOnly("POST", "/health")).toBe(true);
    expect(isAllowedUnderReadOnly("POST", "/metrics")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Read endpoints still work
// ---------------------------------------------------------------------------

describe("read endpoints under OPENCRED_READ_ONLY=true", () => {
  let app: Hono;

  beforeEach(() => {
    process.env.OPENCRED_READ_ONLY = "true";
    app = createTestApp({ devModeNoAuth: true });
    setActiveSigner(testKey.signer);
  });

  it("GET /health returns 200", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);
  });

  it("GET /v1/schemas returns 200", async () => {
    const res = await app.request("/v1/schemas");
    expect(res.status).toBe(200);
  });

  it("GET /v1/schemas/:id returns 200", async () => {
    const res = await app.request("/v1/schemas/functional-identity/v1");
    expect(res.status).toBe(200);
  });

  it("POST /v1/credentials/verify returns a verify response (not 405)", async () => {
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
    // The verifier returns 200 with a verdict for a syntactically valid
    // credential. The point of THIS test is that read-only mode did NOT
    // intercept the request with 405.
    expect(res.status).not.toBe(405);
    expect(res.status).toBe(200);
  });

  it("POST /v1/keys/resolve returns 503 (DeDi not configured) — proves it reached the handler", async () => {
    const res = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verificationMethod: "did:web:example.org#key-0" }),
    });
    expect(res.status).toBe(503);
  });

  it("GET /v1/keys/resolve is allowed", async () => {
    const res = await app.request(
      "/v1/keys/resolve?verificationMethod=did:web:example.org%23key-0",
    );
    // 503 because DeDi isn't configured, NOT 405. The point is that the
    // request reached the handler under read-only mode.
    expect(res.status).toBe(503);
  });

  it("POST /v1/credentials/revocation-hash returns 200", async () => {
    const res = await app.request("/v1/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: { id: "urn:uuid:test", type: ["VC"] } }),
    });
    expect(res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Write endpoints are blocked
// ---------------------------------------------------------------------------

describe("write endpoints under OPENCRED_READ_ONLY=true", () => {
  let app: Hono;

  beforeEach(() => {
    process.env.OPENCRED_READ_ONLY = "true";
    app = createTestApp({ devModeNoAuth: true });
    setActiveSigner(testKey.signer);
  });

  async function expectReadOnly405(res: Response): Promise<void> {
    expect(res.status).toBe(405);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("READ_ONLY_MODE");
  }

  it("POST /v1/credentials/issue → 405 READ_ONLY_MODE", async () => {
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(VALID_ISSUE_REQUEST),
    });
    await expectReadOnly405(res);
  });

  it("POST /v1/credentials/batch → 405", async () => {
    const res = await app.request("/v1/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ csvContent: "name\nFoo", schemaId: "functional-identity/v1" }),
    });
    await expectReadOnly405(res);
  });

  it("POST /v1/credentials/revoke → 405", async () => {
    const res = await app.request("/v1/credentials/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash: "a".repeat(64) }),
    });
    await expectReadOnly405(res);
  });

  it("POST /v1/keys/publish → 405", async () => {
    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:web:example.org", document: {} }),
    });
    await expectReadOnly405(res);
  });

  it("POST /v1/schemas/generate → 405", async () => {
    const res = await app.request("/v1/schemas/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fields: { name: "string" } }),
    });
    await expectReadOnly405(res);
  });

  it("POST /v1/dedi/namespace/ensure → 405", async () => {
    const res = await app.request("/v1/dedi/namespace/ensure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ namespace: "test" }),
    });
    await expectReadOnly405(res);
  });
});

// ---------------------------------------------------------------------------
// Default (read-only OFF) — every write endpoint still works
// ---------------------------------------------------------------------------

describe("default mode (OPENCRED_READ_ONLY=false) keeps writes open", () => {
  let app: Hono;

  beforeEach(() => {
    process.env.OPENCRED_READ_ONLY = "false";
    app = createTestApp({ devModeNoAuth: true });
    setActiveSigner(testKey.signer);
  });

  it("POST /v1/credentials/issue does not return 405", async () => {
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(VALID_ISSUE_REQUEST),
    });
    expect(res.status).not.toBe(405);
  });
});
