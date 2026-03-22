/**
 * Endpoint round-trip tests using Hono's app.request().
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { createTestApp, generateTestKey, VALID_ISSUE_REQUEST, EDUCATION_SUBJECT } from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import type { Hono } from "hono";
import type { TestKeyPair } from "./helpers.js";

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp();
  setActiveSigner(testKey.signer);
});

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

describe("GET /health", () => {
  it("returns 200 with status ok", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.status).toBe("ok");
    expect(body.signingKeyLoaded).toBe(true);
    expect(body).toHaveProperty("timestamp");
  });
});

// ---------------------------------------------------------------------------
// GET /schemas
// ---------------------------------------------------------------------------

describe("GET /schemas", () => {
  it("returns list of schema IDs", async () => {
    const res = await app.request("/schemas");
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body).toHaveProperty("schemas");
    expect(Array.isArray(body.schemas)).toBe(true);
    expect(body.schemas.length).toBeGreaterThan(0);

    const ids = body.schemas.map((s: { id: string }) => s.id);
    expect(ids).toContain("education");
    expect(ids).toContain("employment");
    expect(ids).toContain("identity");
  });

  it("returns individual schema by ID", async () => {
    const res = await app.request("/schemas/education");
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.id).toBe("education");
    expect(body).toHaveProperty("schema");
    expect(body).toHaveProperty("contextUrl");
  });

  it("returns 404 for unknown schema", async () => {
    const res = await app.request("/schemas/nonexistent");
    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// POST /credentials/issue
// ---------------------------------------------------------------------------

describe("POST /credentials/issue", () => {
  it("issues a signed vc-jwt credential", async () => {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(VALID_ISSUE_REQUEST),
    });

    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.proofFormat).toBe("vc-jwt");
    expect(body.isCompactToken).toBe(false);
    expect(body.credential).toHaveProperty("proof");
    expect(body.credential.proof).toHaveProperty("jwt");
    expect(body.credential.issuer).toBe("did:key:test-issuer");
  });

  it("returns 400 for invalid schema subject", async () => {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        credentialSubject: { name: "Missing fields" },
      }),
    });

    expect(res.status).toBe(400);
  });

  it("returns 400 for missing required fields", async () => {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schemaId: "education" }),
    });

    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// POST /credentials/verify
// ---------------------------------------------------------------------------

describe("POST /credentials/verify", () => {
  it("verifies a signed credential as valid", async () => {
    // Issue a credential with data-integrity format (includes verificationMethod in proof)
    const issueRes = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        issuerDid: testKey.signer.id.split("#")[0],
        proofFormat: "data-integrity",
      }),
    });

    expect(issueRes.status).toBe(200);
    const issued = await issueRes.json();

    // Now verify it
    const verifyRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: JSON.stringify(issued.credential),
      }),
    });

    expect(verifyRes.status).toBe(200);
    const result = await verifyRes.json();
    expect(result.valid).toBe(true);
    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "signature", passed: true }),
      ]),
    );
  });

  it("returns invalid for tampered credential", async () => {
    // Issue with data-integrity format
    const issueRes = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        issuerDid: testKey.signer.id.split("#")[0],
        proofFormat: "data-integrity",
      }),
    });

    const issued = await issueRes.json();

    // Tamper with it
    const tampered = { ...issued.credential };
    tampered.credentialSubject = { ...tampered.credentialSubject, name: "Tampered Name" };

    const verifyRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: JSON.stringify(tampered),
      }),
    });

    expect(verifyRes.status).toBe(200);
    const result = await verifyRes.json();
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// POST /credentials/revocation-hash
// ---------------------------------------------------------------------------

describe("POST /credentials/revocation-hash", () => {
  it("computes a revocation hash", async () => {
    const res = await app.request("/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          type: ["VerifiableCredential"],
          issuer: "did:key:test",
          credentialSubject: EDUCATION_SUBJECT,
        },
      }),
    });

    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body).toHaveProperty("hash");
    expect(typeof body.hash).toBe("string");
    expect(body.hash.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// POST /credentials/batch
// ---------------------------------------------------------------------------

describe("POST /credentials/batch", () => {
  it("starts a batch job and returns jobId", async () => {
    const csvContent = [
      "name,degree,institution,dateConferred",
      "Alice,BS,Stanford,2025-06-01",
      "Bob,MS,MIT,2025-07-01",
    ].join("\n");

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent,
        schemaId: "education",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });

    expect(res.status).toBe(202);

    const body = await res.json();
    expect(body).toHaveProperty("jobId");
    expect(body.validCount).toBe(2);
    expect(body.totalCount).toBe(2);
    expect(body.headers).toEqual(["name", "degree", "institution", "dateConferred"]);
  });

  it("returns batch progress", async () => {
    const csvContent = "name,degree,institution,dateConferred\nAlice,BS,Stanford,2025-06-01\n";

    const startRes = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent,
        schemaId: "education",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
      }),
    });

    const { jobId } = await startRes.json();

    // Wait briefly for background processing
    await new Promise((resolve) => setTimeout(resolve, 200));

    const progressRes = await app.request(`/credentials/batch/${jobId}`);
    expect(progressRes.status).toBe(200);

    const progress = await progressRes.json();
    expect(progress.jobId).toBe(jobId);
    expect(progress.total).toBe(1);
    expect(typeof progress.completed).toBe("number");
  });

  it("returns 404 for unknown job ID", async () => {
    const res = await app.request("/credentials/batch/nonexistent-job-id");
    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// 404 handler
// ---------------------------------------------------------------------------

describe("404 handler", () => {
  it("returns 404 for unknown endpoints", async () => {
    const res = await app.request("/nonexistent");
    expect(res.status).toBe(404);

    const body = await res.json();
    expect(body.error.code).toBe("NOT_FOUND");
  });
});
