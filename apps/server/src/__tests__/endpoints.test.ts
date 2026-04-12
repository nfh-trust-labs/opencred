/**
 * Endpoint round-trip tests using Hono's app.request().
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import {
  createTestApp,
  generateTestKey,
  VALID_ISSUE_REQUEST,
  FUNCTIONAL_IDENTITY_SUBJECT,
} from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import { sanitizeChecksForServerResponse, buildVerifyResponseBody } from "../routes/credentials.js";
import type { Hono } from "hono";
import type { TestKeyPair } from "./helpers.js";

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  // These tests exercise endpoint behaviour, not the auth path. Use the
  // explicit dev-mode opt-out so requests can omit the Authorization header.
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);
});

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

describe("GET /health", () => {
  it("returns 200 with status ok", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
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

    const body = (await res.json()) as { schemas: { id: string; source?: { kind: string } }[] };
    expect(body).toHaveProperty("schemas");
    expect(Array.isArray(body.schemas)).toBe(true);
    expect(body.schemas.length).toBeGreaterThan(0);

    const ids = body.schemas.map((s) => s.id);
    expect(ids).toContain("functional-identity/v1");
    expect(ids).toContain("immunization/v1");
    expect(ids).toContain("electricity/v1");
  });

  it("includes source provenance for every schema", async () => {
    const res = await app.request("/schemas");
    const body = (await res.json()) as {
      schemas: { id: string; source: { kind: string; upstreamOwner: string } }[];
    };
    for (const entry of body.schemas) {
      expect(entry.source).toBeDefined();
      expect(["defined", "referenced"]).toContain(entry.source.kind);
      expect(typeof entry.source.upstreamOwner).toBe("string");
    }
  });

  it("returns individual schema by ID", async () => {
    const res = await app.request("/schemas/functional-identity/v1");
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.id).toBe("functional-identity/v1");
    expect(body).toHaveProperty("schema");
    expect(body).toHaveProperty("source");
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

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.proofFormat).toBe("vc-jwt");
    expect(body.isCompactToken).toBe(false);
    expect(body.credential).toHaveProperty("proof");
    expect((body.credential as Record<string, unknown>).proof).toHaveProperty("jwt");
    expect((body.credential as Record<string, unknown>).issuer).toBe("did:key:test-issuer");
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
      body: JSON.stringify({ schemaId: "functional-identity/v1" }),
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
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };

    // Now verify it
    const verifyRes = await app.request("/credentials/verify", {
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

    const issued = (await issueRes.json()) as {
      credential: Record<string, unknown> & { credentialSubject: Record<string, unknown> };
    };

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
    const result = (await verifyRes.json()) as Record<string, unknown>;
    expect(result.valid).toBe(false);
  });

  it("accepts an OPENCRED1: compressed credential string", async () => {
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
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };

    const { compressCredentialForQr } = await import("../packaging/qr-generator.js");
    const compressed = compressCredentialForQr(
      issued.credential as Parameters<typeof compressCredentialForQr>[0],
    );

    const verifyRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: compressed }),
    });

    expect(verifyRes.status).toBe(200);
    const result = (await verifyRes.json()) as Record<string, unknown>;
    expect(result.valid).toBe(true);
  });

  it("accepts a VC-JWT compact string", async () => {
    const issueRes = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        issuerDid: testKey.signer.id.split("#")[0],
        proofFormat: "vc-jwt",
      }),
    });
    expect(issueRes.status).toBe(200);
    const issued = (await issueRes.json()) as {
      credential: { proof: { jwt: string } };
    };
    const jwtCompact = issued.credential.proof.jwt;

    const verifyRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: jwtCompact }),
    });

    expect(verifyRes.status).toBe(200);
    const result = (await verifyRes.json()) as Record<string, unknown>;
    expect(result).toHaveProperty("valid");
    expect(result).toHaveProperty("checks");
  });

  it("rejects unrecognized credential format with 400", async () => {
    const verifyRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: "not-a-valid-format" }),
    });

    expect(verifyRes.status).toBe(400);
    const body = (await verifyRes.json()) as { error: { message: string } };
    expect(body.error.message).toBe("Unrecognized credential format");
  });

  it("backward compatibility: raw JSON string still works", async () => {
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
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };

    const verifyRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: JSON.stringify(issued.credential) }),
    });

    expect(verifyRes.status).toBe(200);
    const result = (await verifyRes.json()) as Record<string, unknown>;
    expect(result.valid).toBe(true);
  });

  // SECURITY: Per CLAUDE.md invariant #5, the /credentials/verify response must
  // not leak operator config or parser errors through `checks[].detail` strings.
  // The desktop IPC handler is allowed full detail (trusted user on both sides),
  // but an unauthenticated remote caller to the server must receive only the
  // sanitized shape. See nfh-trust-labs/opencred PR #320 review.
  //
  // These tests drive the route's response-builder helper directly with
  // known `detail` strings that include an operator CSCA subject DN and an
  // X.509 parser error — the exact two classes of leak the review flagged.
  // Going through the helper (rather than a full HTTP round-trip) keeps the
  // test focused on the sanitization contract and avoids coupling to the
  // verifier's unrelated fixture-setup requirements.
  describe("response sanitization (invariant #5)", () => {
    const SENSITIVE_CSCA_DN = "CN=CSCA Test Root, O=Test Country, C=XX";
    const SENSITIVE_PARSER_ERROR =
      "Failed to parse configured trust anchors: unable to load PEM at /private/etc/opencred/trust/root.pem";

    it("sanitizeChecksForServerResponse drops detail from every check", () => {
      const rawChecks = [
        { name: "signature", passed: true, detail: "signature valid" },
        { name: "date", passed: true },
        {
          name: "x509-chain",
          passed: true,
          // Simulates the production success-path detail that embeds the
          // operator's CSCA subject DN — MUST be stripped.
          detail: `DSC verified (CN=Test DSC), chain depth: 2, anchored to ${SENSITIVE_CSCA_DN}`,
        },
        {
          name: "x509-chain-parse",
          passed: false,
          detail: SENSITIVE_PARSER_ERROR,
        },
      ];

      const sanitized = sanitizeChecksForServerResponse(rawChecks);

      expect(sanitized).toHaveLength(rawChecks.length);
      for (const check of sanitized) {
        expect(Object.keys(check).sort()).toEqual(["name", "passed"]);
        expect((check as Record<string, unknown>).detail).toBeUndefined();
      }

      // Serialized form must not contain either sensitive string.
      const serialized = JSON.stringify(sanitized);
      expect(serialized).not.toContain(SENSITIVE_CSCA_DN);
      expect(serialized).not.toContain(SENSITIVE_PARSER_ERROR);
      expect(serialized).not.toContain("/private/etc/opencred");

      // Names + passed flags survive so callers can still identify which
      // check failed.
      expect(sanitized.map((c) => c.name)).toEqual([
        "signature",
        "date",
        "x509-chain",
        "x509-chain-parse",
      ]);
      expect(sanitized.map((c) => c.passed)).toEqual([true, true, true, false]);
    });

    it("buildVerifyResponseBody returns the sanitized shape for a verified credential and strips the CSCA DN", () => {
      const result = buildVerifyResponseBody({
        verified: true,
        code: "VALID",
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
          {
            name: "x509-chain",
            passed: true,
            detail: `DSC verified (CN=Test DSC), chain depth: 2, anchored to ${SENSITIVE_CSCA_DN}`,
          },
        ],
      });

      expect(result.valid).toBe(true);
      expect(result.code).toBe("VALID");
      expect(result.message).toBe("Credential is valid.");
      expect(result.checks).toHaveLength(3);

      for (const check of result.checks) {
        expect(Object.keys(check).sort()).toEqual(["name", "passed"]);
      }

      // Global guard: the CSCA DN must not appear anywhere in the serialized
      // response body.
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain(SENSITIVE_CSCA_DN);
    });

    it("buildVerifyResponseBody uses a generic message on failure and strips the parser error", () => {
      const result = buildVerifyResponseBody({
        verified: false,
        code: "INVALID",
        checks: [
          { name: "signature", passed: true },
          {
            name: "x509-chain",
            passed: false,
            // The exact class of string flagged by the review: a parser
            // error that echoes a filesystem path from operator config.
            detail: SENSITIVE_PARSER_ERROR,
          },
          { name: "date", passed: true },
        ],
      });

      expect(result.valid).toBe(false);
      expect(result.code).toBe("INVALID");

      // The message must be the stable fallback — NOT the detail of the
      // failing check (that was the buggy behaviour this fix addresses).
      expect(result.message).toBe("Verification failed.");

      // Every check — passing or failing — must be sanitized.
      for (const check of result.checks) {
        expect(Object.keys(check).sort()).toEqual(["name", "passed"]);
      }

      // Global guard: the parser error and filesystem path must not appear
      // anywhere in the serialized response.
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain(SENSITIVE_PARSER_ERROR);
      expect(serialized).not.toContain("/private/etc/opencred");

      // The failing check survives (name + passed) so callers can still
      // identify which check failed; only the detail is stripped.
      const failingCheck = result.checks.find((c) => c.passed === false);
      expect(failingCheck).toBeDefined();
      expect(failingCheck?.name).toBe("x509-chain");
    });

    it("end-to-end: /credentials/verify response contains no `detail` fields when the verifier reports an error on a bad credential", async () => {
      // This exercises the full HTTP path with a deliberately malformed
      // credential so the route reaches the sanitization code. The verifier
      // will fail fast (unknown / missing proof etc.); whatever its detail
      // strings are, none of them must leak into the HTTP response.
      const verifyRes = await app.request("/credentials/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: JSON.stringify({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            type: ["VerifiableCredential"],
            issuer: "did:key:z6MkfakeIssuerDoesNotResolveXYZ",
            credentialSubject: { id: "did:example:subject" },
            proof: {
              type: "DataIntegrityProof",
              cryptosuite: "ecdsa-rdfc-2019",
              created: "2025-01-01T00:00:00Z",
              verificationMethod:
                "did:key:z6MkfakeIssuerDoesNotResolveXYZ#z6MkfakeIssuerDoesNotResolveXYZ",
              proofPurpose: "assertionMethod",
              proofValue: "z3NotAValidSignature",
            },
          }),
        }),
      });

      // The route either verifies (returning 200 with `valid: false`) or
      // throws an OpenCredError (returning 4xx). Either way, if we get JSON
      // back it must conform to the sanitized shape.
      const bodyText = await verifyRes.text();

      // If verification completed, assert sanitization on the response body.
      if (verifyRes.status === 200) {
        const body = JSON.parse(bodyText) as {
          valid: boolean;
          code: string;
          message: string;
          checks: Array<Record<string, unknown>>;
        };
        expect(
          body.message === "Credential is valid." || body.message === "Verification failed.",
        ).toBe(true);
        for (const check of body.checks) {
          expect(Object.keys(check).sort()).toEqual(["name", "passed"]);
        }
      }
    });
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
          credentialSubject: FUNCTIONAL_IDENTITY_SUBJECT,
        },
      }),
    });

    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toHaveProperty("hash");
    expect(typeof body.hash).toBe("string");
    expect((body.hash as string).length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// POST /credentials/batch
// ---------------------------------------------------------------------------

describe("POST /credentials/batch", () => {
  it("starts a batch job and returns jobId", async () => {
    const csvContent = [
      "name,role,validFrom",
      "Alice,Medical Practitioner,2025-06-01T00:00:00Z",
      "Bob,Registered Nurse,2025-06-01T00:00:00Z",
    ].join("\n");

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });

    expect(res.status).toBe(202);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toHaveProperty("jobId");
    expect(body.validCount).toBe(2);
    expect(body.totalCount).toBe(2);
    expect(body.headers).toEqual(["name", "role", "validFrom"]);
  });

  it("returns batch progress", async () => {
    const csvContent = "name,role,validFrom\nAlice,Medical Practitioner,2025-06-01T00:00:00Z\n";

    const startRes = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
      }),
    });

    const { jobId } = (await startRes.json()) as { jobId: string };

    // Wait briefly for background processing
    await new Promise((resolve) => setTimeout(resolve, 200));

    const progressRes = await app.request(`/credentials/batch/${jobId}`);
    expect(progressRes.status).toBe(200);

    const progress = (await progressRes.json()) as Record<string, unknown>;
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
// Issuer branding customization
// ---------------------------------------------------------------------------

describe("issuer branding customization", () => {
  it("POST /credentials/issue accepts customization and returns packaged output", async () => {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        packageFormats: ["json-ld"],
        customization: {
          primaryColor: "#ff5500",
          issuerDisplayName: "Acme Corp",
        },
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.credential).toHaveProperty("proof");
    expect(body.packagedOutputs).toBeDefined();
  });

  it("POST /credentials/issue rejects invalid hex color", async () => {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        customization: {
          primaryColor: "not-a-color",
        },
      }),
    });

    expect(res.status).toBe(400);
  });

  it("POST /credentials/issue rejects non-data-URI logo", async () => {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        customization: {
          logoDataUri: "https://example.com/logo.png",
        },
      }),
    });

    expect(res.status).toBe(400);
  });

  it("POST /credentials/issue accepts valid data URI logo", async () => {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        customization: {
          logoDataUri: "data:image/png;base64,iVBORw0KGgo=",
        },
      }),
    });

    expect(res.status).toBe(200);
  });

  it("POST /credentials/package accepts customization", async () => {
    // First issue a credential
    const issueRes = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(VALID_ISSUE_REQUEST),
    });
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };

    // Package with customization
    const res = await app.request("/credentials/package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: issued.credential,
        formats: ["json-ld"],
        customization: {
          primaryColor: "#00aa33",
          issuerDisplayName: "Test Issuer",
        },
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { outputs: unknown[] };
    expect(body.outputs).toBeDefined();
    expect(body.outputs.length).toBeGreaterThan(0);
  });

  it("POST /credentials/batch accepts customization", async () => {
    const csvContent = [
      "name,role,validFrom",
      "Alice,Medical Practitioner,2025-06-01T00:00:00Z",
    ].join("\n");

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
        proofFormat: "vc-jwt",
        customization: {
          primaryColor: "#123456",
          issuerDisplayName: "Batch Issuer",
        },
      }),
    });

    expect(res.status).toBe(202);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toHaveProperty("jobId");
  });
});

// ---------------------------------------------------------------------------
// 404 handler
// ---------------------------------------------------------------------------

describe("404 handler", () => {
  it("returns 404 for unknown endpoints", async () => {
    const res = await app.request("/nonexistent");
    expect(res.status).toBe(404);

    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("NOT_FOUND");
  });
});
