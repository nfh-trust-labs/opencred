/**
 * /v1 smoke test — exercises the four endpoints required by issue #301:
 *
 *   GET  /v1/health
 *   GET  /v1/keys
 *   POST /v1/credentials/issue
 *   POST /v1/credentials/verify
 *
 * The server is bootstrapped fully in-process via the test app factory and
 * exercised through Hono's request() helper (the equivalent of fastify.inject
 * for Hono — no real socket is opened).
 *
 * SECURITY: every assertion in this file double-checks that key material
 * never appears in any response body. The signing key is loaded once at
 * startup from the local filesystem and never crosses the HTTP boundary.
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import type { Hono } from "hono";

import { createTestApp, generateTestKey, EDUCATION_SUBJECT } from "./helpers.js";
import type { TestKeyPair } from "./helpers.js";
import { loadSigningKey, setActiveSigner } from "../signing/key-manager.js";
import { resetConfig, loadConfig } from "../config.js";

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  // devModeNoAuth: smoke tests exercise endpoint logic, not auth.
  // Auth is tested separately in auth.test.ts.
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);
});

// ---------------------------------------------------------------------------
// GET /v1/health
// ---------------------------------------------------------------------------

describe("GET /v1/health", () => {
  it("returns 200 with status ok and a timestamp", async () => {
    const res = await app.request("/v1/health");
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
    expect(body.signingKeyLoaded).toBe(true);
    expect(typeof body.timestamp).toBe("string");
  });

  it("never leaks key material", async () => {
    const res = await app.request("/v1/health");
    const text = await res.text();
    // Hard guarantees: no PEM blocks, no JWK private fields.
    expect(text).not.toContain("PRIVATE KEY");
    expect(text).not.toContain('"d"');
  });
});

// ---------------------------------------------------------------------------
// GET /v1/keys
// ---------------------------------------------------------------------------

describe("GET /v1/keys", () => {
  it("returns the active signer's public metadata only", async () => {
    const res = await app.request("/v1/keys");
    expect(res.status).toBe(200);

    const body = (await res.json()) as { keys: Array<Record<string, unknown>> };
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys).toHaveLength(1);

    const key = body.keys[0]!;
    expect(key.id).toBe(testKey.signer.id);
    expect(key.fingerprint).toBe(testKey.signer.metadata.fingerprint);
    expect(key.algorithm).toBe("P-256");
    expect(key.type).toBe("software");
    expect(key.source).toBe("software-file");

    // Hard security check: the response must not contain any private key bits.
    const keyText = JSON.stringify(body);
    expect(keyText).not.toContain("PRIVATE KEY");
    expect(keyText).not.toContain('"d"');
    expect(keyText).not.toContain("BEGIN");
  });

  it("returns an empty array when no signer is configured", async () => {
    setActiveSigner(null);
    const res = await app.request("/v1/keys");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keys: unknown[]; message?: string };
    expect(body.keys).toHaveLength(0);
    expect(body.message).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// POST /v1/credentials/issue
// ---------------------------------------------------------------------------

describe("POST /v1/credentials/issue", () => {
  it("issues a signed vc-jwt education credential", async () => {
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        credentialSubject: EDUCATION_SUBJECT,
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });

    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.proofFormat).toBe("vc-jwt");
    expect(body.isCompactToken).toBe(false);

    const credential = body.credential as Record<string, unknown>;
    expect(credential).toHaveProperty("proof");
    expect((credential.proof as Record<string, unknown>).jwt).toBeDefined();
    expect(credential.issuer).toBe(testKey.signer.id.split("#")[0]);

    // No private key material in the response, period.
    const text = JSON.stringify(body);
    expect(text).not.toContain("PRIVATE KEY");
    expect(text).not.toContain('"d"');
  });

  it("rejects requests that include a private key field with 400", async () => {
    // The prompt is explicit: the API must NEVER accept a private key as
    // input. Any attempt to smuggle one in must be rejected with a 400 by
    // the rejectKeyMaterial defense-in-depth check.
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        credentialSubject: EDUCATION_SUBJECT,
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat: "vc-jwt",
        privateKey: "-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----",
      }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.message).toMatch(/forbidden|never accepts/);
  });

  // The PEM scanner must fire for every common `-----BEGIN … PRIVATE KEY-----`
  // header the OpenSSL toolchain produces, not just PKCS#8. We feed the key
  // into a NON-forbidden field (`notes`) so the first-pass FORBIDDEN_REQUEST_KEYS
  // check is bypassed and the PEM scanner is exercised directly. The original
  // version of this test only asserted the PKCS#8 case, and because it used
  // `privateKey` as the field name it short-circuited on FORBIDDEN_REQUEST_KEYS
  // anyway — which meant the PEM scanner was never actually exercised at all.
  it.each([
    ["PKCS#8", "-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----"],
    [
      "PKCS#8 encrypted",
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIG...\n-----END ENCRYPTED PRIVATE KEY-----",
    ],
    ["PKCS#1 RSA", "-----BEGIN RSA PRIVATE KEY-----\nMIG...\n-----END RSA PRIVATE KEY-----"],
    ["SEC1 EC", "-----BEGIN EC PRIVATE KEY-----\nMIG...\n-----END EC PRIVATE KEY-----"],
    [
      "OpenSSH",
      "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz...\n-----END OPENSSH PRIVATE KEY-----",
    ],
  ])("rejects %s PEM strings embedded in a non-forbidden field with 400", async (_label, pem) => {
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        credentialSubject: {
          ...EDUCATION_SUBJECT,
          // `notes` is not in FORBIDDEN_REQUEST_KEYS — this exercises the
          // PEM scanner specifically, not the first-pass field-name check.
          notes: pem,
        },
        validFrom: "2025-06-15T00:00:00Z",
      }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
    // The error message must mention the PEM path — not the forbidden-field
    // path — otherwise the test is passing for the wrong reason.
    expect(body.error.message).toMatch(/looks like a PEM-encoded private key/);
  });

  it("returns 400 when credentialSubject does not satisfy the schema", async () => {
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        credentialSubject: { name: "Missing required fields" },
        validFrom: "2025-06-15T00:00:00Z",
      }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("SCHEMA_VALIDATION_ERROR");
  });
});

// ---------------------------------------------------------------------------
// Software signer loader (the boot-time path the Docker image uses)
// ---------------------------------------------------------------------------

describe("loadSigningKey() boot path", () => {
  it("loads a key from the configured local path and exposes only metadata", async () => {
    // Point the loader at the local file the test fixture wrote at startup,
    // then assert the only thing the API surfaces is metadata.
    process.env.OPENCRED_KEY_PATH = testKey.pemPath;
    process.env.OPENCRED_KEY_LABEL = "smoke-test-loader";
    resetConfig();
    loadConfig();
    const signer = loadSigningKey();
    expect(signer).not.toBeNull();
    expect(signer!.algorithm).toBe("P-256");

    // The /v1/keys endpoint must never contain anything that resembles a
    // PEM block, JWK private parameter, or hex-encoded raw key.
    const res = await app.request("/v1/keys");
    const text = await res.text();
    expect(text).not.toContain("BEGIN");
    expect(text).not.toContain("END");
    expect(text).not.toContain("PRIVATE");
    expect(text).not.toMatch(/"d"\s*:/);

    // Cleanup
    delete process.env.OPENCRED_KEY_PATH;
    delete process.env.OPENCRED_KEY_LABEL;
  });
});

// ---------------------------------------------------------------------------
// POST /v1/credentials/verify
// ---------------------------------------------------------------------------

describe("POST /v1/credentials/verify", () => {
  it("verifies a freshly issued data-integrity credential as valid", async () => {
    // 1. Issue
    const issueRes = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        credentialSubject: EDUCATION_SUBJECT,
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat: "data-integrity",
      }),
    });
    expect(issueRes.status).toBe(200);
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };

    // 2. Verify
    const verifyRes = await app.request("/v1/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: JSON.stringify(issued.credential),
      }),
    });

    expect(verifyRes.status).toBe(200);
    const result = (await verifyRes.json()) as Record<string, unknown>;
    expect(result.valid).toBe(true);
    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "signature", passed: true })]),
    );
  });

  it("returns valid=false for a tampered credential", async () => {
    const issueRes = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        credentialSubject: EDUCATION_SUBJECT,
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat: "data-integrity",
      }),
    });
    const issued = (await issueRes.json()) as {
      credential: Record<string, unknown> & { credentialSubject: Record<string, unknown> };
    };
    const tampered = {
      ...issued.credential,
      credentialSubject: { ...issued.credential.credentialSubject, name: "Mallory" },
    };

    const verifyRes = await app.request("/v1/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: JSON.stringify(tampered) }),
    });

    expect(verifyRes.status).toBe(200);
    const result = (await verifyRes.json()) as Record<string, unknown>;
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Defense-in-depth: every POST route must reject key material
// ---------------------------------------------------------------------------
//
// CLAUDE.md rule 1 says "No endpoint, no function, no code path should accept
// an issuer's private key as input." The rejectKeyMaterial scanner is
// supposed to run on every POST route. These tests pin that contract so no
// future route can forget the guard.

describe("rejectKeyMaterial — defense-in-depth on every POST route", () => {
  const sec1Pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIAAAAA...\n-----END EC PRIVATE KEY-----";

  it("POST /v1/credentials/batch rejects PEM strings in csvContent", async () => {
    const res = await app.request("/v1/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        // Smuggle a PEM block inside the CSV content.
        csvContent: `name,email,notes\nAlice,alice@example.com,"${sec1Pem.replace(/\n/g, " ")}"\n`,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-15T00:00:00Z",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.message).toMatch(/PEM-encoded private key/);
  });

  it("POST /v1/credentials/revocation-hash rejects PEM strings in credential", async () => {
    const res = await app.request("/v1/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: {
          id: "urn:test:1",
          notes: sec1Pem,
        },
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.message).toMatch(/PEM-encoded private key/);
  });

  it("POST /v1/credentials/revocation-hash/batch rejects PEM strings", async () => {
    const res = await app.request("/v1/credentials/revocation-hash/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credentials: [{ id: "urn:test:1", notes: sec1Pem }],
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });

  it("POST /v1/credentials/package rejects PEM strings in credential", async () => {
    const res = await app.request("/v1/credentials/package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: {
          id: "urn:test:1",
          notes: sec1Pem,
        },
        formats: ["json"],
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });
});
