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
import { setDeDiClient, resetDeDiClient } from "../dedi-singleton.js";
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
  it("returns 200 with ready=true when signing key is loaded", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
    expect(body.ready).toBe(true);
    expect(body.signingKeyLoaded).toBe(true);
    expect(body).toHaveProperty("timestamp");
  });

  it("returns 503 with ready=false when signing key is not loaded", async () => {
    setActiveSigner(null);

    const res = await app.request("/health");
    expect(res.status).toBe(503);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
    expect(body.ready).toBe(false);
    expect(body.signingKeyLoaded).toBe(false);
    expect(body).toHaveProperty("timestamp");
  });

  it("returns dediConfigured=false when DeDi client is not set", async () => {
    resetDeDiClient();
    const res = await app.request("/health");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.dediConfigured).toBe(false);
  });

  it("returns dediConfigured=true when DeDi client is set", async () => {
    const mockClient = { fake: true } as never;
    setDeDiClient(mockClient);
    const res = await app.request("/health");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.dediConfigured).toBe(true);
    resetDeDiClient();
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

  // -------------------------------------------------------------------------
  // HIGH-02: subjectDid URI validation
  // -------------------------------------------------------------------------
  //
  // The Zod schema refines `subjectDid` via `isValidSubjectUri` from
  // `@opencred/vc-core`. These tests target the route boundary so we see a
  // clean 400 with a Zod-shaped error rather than a CryptoError 500 from the
  // builder's defense-in-depth check.
  describe("subjectDid URI validation (HIGH-02)", () => {
    async function issue(subjectDid: unknown): Promise<Response> {
      return app.request("/credentials/issue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...VALID_ISSUE_REQUEST, subjectDid }),
      });
    }

    it("rejects javascript: scheme with 400 and a Zod error path on subjectDid", async () => {
      const res = await issue("javascript:alert(1)");
      expect(res.status).toBe(400);

      const body = (await res.json()) as { error: { code: string; details?: unknown } };
      expect(body.error.code).toBe("VALIDATION_ERROR");
      const details = body.error.details as Array<{ path: string; message: string }>;
      expect(details.some((d) => d.path === "subjectDid")).toBe(true);
    });

    it("rejects data: scheme with 400", async () => {
      const res = await issue("data:text/html,<script>alert(1)</script>");
      expect(res.status).toBe(400);
    });

    it("rejects empty string (not a URI at all)", async () => {
      const res = await issue("");
      expect(res.status).toBe(400);
    });

    it("rejects free-form non-URI strings", async () => {
      const res = await issue("not-a-uri");
      expect(res.status).toBe(400);
    });

    it("rejects path-shaped inputs that look like file paths", async () => {
      const res = await issue("../etc/passwd");
      expect(res.status).toBe(400);
    });

    it("accepts a valid did:web URI", async () => {
      const res = await issue("did:web:example.com");
      expect(res.status).toBe(200);
    });

    it("accepts a valid urn:uuid URI", async () => {
      const res = await issue("urn:uuid:550e8400-e29b-41d4-a716-446655440000");
      expect(res.status).toBe(200);
    });

    it("accepts a valid https:// URI", async () => {
      const res = await issue("https://example.com/users/42");
      expect(res.status).toBe(200);
    });
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
      issued.credential as unknown as Parameters<typeof compressCredentialForQr>[0],
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
// POST /credentials/revoke
// ---------------------------------------------------------------------------

describe("POST /credentials/revoke", () => {
  it("returns 503 when DeDi is not configured", async () => {
    resetDeDiClient();
    const res = await app.request("/credentials/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash: "a".repeat(64) }),
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("DEDI_NOT_CONFIGURED");
  });

  it("returns 400 when neither credential nor hash is provided", async () => {
    const mockClient = {
      publishRevocationHash: async () => ({
        hash: "x",
        revoked: true as const,
        revokedAt: new Date().toISOString(),
      }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/credentials/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    resetDeDiClient();
  });

  it("returns 400 when hash is invalid (wrong length)", async () => {
    const mockClient = {
      publishRevocationHash: async () => ({
        hash: "x",
        revoked: true as const,
        revokedAt: new Date().toISOString(),
      }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/credentials/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash: "tooshort" }),
    });
    expect(res.status).toBe(400);
    resetDeDiClient();
  });

  it("revokes by hash when DeDi is configured", async () => {
    const revokedAt = new Date().toISOString();
    const mockClient = {
      publishRevocationHash: async (hash: string) => ({ hash, revoked: true as const, revokedAt }),
    } as never;
    setDeDiClient(mockClient);

    const hash = "a".repeat(64);
    const res = await app.request("/credentials/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { hash: string; revoked: boolean; revokedAt: string };
    expect(body.hash).toBe(hash);
    expect(body.revoked).toBe(true);
    expect(body.revokedAt).toBe(revokedAt);
    resetDeDiClient();
  });

  it("revokes by credential (computes hash) when DeDi is configured", async () => {
    const revokedAt = new Date().toISOString();
    const mockClient = {
      publishRevocationHash: async (hash: string) => ({ hash, revoked: true as const, revokedAt }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/credentials/revoke", {
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
    const body = (await res.json()) as { hash: string; revoked: boolean };
    expect(body.revoked).toBe(true);
    expect(typeof body.hash).toBe("string");
    expect(body.hash.length).toBe(64);
    resetDeDiClient();
  });
});

// ---------------------------------------------------------------------------
// POST /credentials/revocation-status
// ---------------------------------------------------------------------------

describe("POST /credentials/revocation-status", () => {
  it("returns 503 when DeDi is not configured", async () => {
    resetDeDiClient();
    const res = await app.request("/credentials/revocation-status", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash: "b".repeat(64) }),
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("DEDI_NOT_CONFIGURED");
  });

  it("queries revocation status when DeDi is configured", async () => {
    const mockClient = {
      queryRevocationHash: async (hash: string) => ({ hash, revoked: false as const }),
    } as never;
    setDeDiClient(mockClient);

    const hash = "c".repeat(64);
    const res = await app.request("/credentials/revocation-status", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { hash: string; revoked: boolean };
    expect(body.hash).toBe(hash);
    expect(body.revoked).toBe(false);
    resetDeDiClient();
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

  it("echoes webhookUrl in 202 response when provided (with configured secret)", async () => {
    // LOW-04: a webhookUrl now requires OPENCRED_WEBHOOK_SECRET. Set it via
    // env before building the app so the config cache picks it up, then
    // scrub it at the end so other tests aren't affected.
    const prevSecret = process.env.OPENCRED_WEBHOOK_SECRET;
    process.env.OPENCRED_WEBHOOK_SECRET = "test-webhook-secret-with-32-characters-minimum";
    try {
      const secretApp = createTestApp({ devModeNoAuth: true });
      setActiveSigner(testKey.signer);
      const csvContent = "name,role,validFrom\nAlice,Medical Practitioner,2025-06-01T00:00:00Z\n";

      const res = await secretApp.request("/credentials/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          csvContent,
          schemaId: "functional-identity/v1",
          issuerDid: testKey.signer.id.split("#")[0],
          validFrom: "2025-06-01T00:00:00Z",
          webhookUrl: "https://example.com/webhook",
        }),
      });

      expect(res.status).toBe(202);

      const body = (await res.json()) as Record<string, unknown>;
      expect(body).toHaveProperty("jobId");
      expect(body.webhookUrl).toBe("https://example.com/webhook");
    } finally {
      if (prevSecret === undefined) {
        delete process.env.OPENCRED_WEBHOOK_SECRET;
      } else {
        process.env.OPENCRED_WEBHOOK_SECRET = prevSecret;
      }
    }
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
        packageFormats: ["json"],
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
        formats: ["json"],
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

// ---------------------------------------------------------------------------
// POST /schemas/generate
// ---------------------------------------------------------------------------

describe("POST /schemas/generate", () => {
  it("generates schema from sample fields", async () => {
    const res = await app.request("/schemas/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fields: { name: "Alice", age: 30, email: "alice@example.com" },
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      schema: { properties: Record<string, unknown> };
      fields: unknown[];
    };
    expect(body.schema).toHaveProperty("properties");
    expect(body.schema.properties.name).toEqual({ type: "string" });
    expect(body.schema.properties.age).toEqual({ type: "integer" });
    expect(body.schema.properties.email).toEqual({ type: "string", format: "email" });
    expect(body.fields).toHaveLength(3);
  });

  it("returns 400 for missing fields", async () => {
    const res = await app.request("/schemas/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
  });

  it("returns 400 for array fields", async () => {
    const res = await app.request("/schemas/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fields: [1, 2, 3] }),
    });
    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// MED-02: Body size limits
// ---------------------------------------------------------------------------
//
// We drive `app.request` with an oversize body AND set `Content-Length`
// so the body-limit middleware's header-based fast path trips. This
// sidesteps Hono's ReadableStream rewrap while still exercising the
// middleware contract.

describe("body size limits (MED-02)", () => {
  it("POST /credentials/issue returns 413 PAYLOAD_TOO_LARGE when body exceeds limit", async () => {
    const prev = process.env.OPENCRED_MAX_BODY_BYTES;
    // Tight cap so a tiny body trips the limit deterministically.
    process.env.OPENCRED_MAX_BODY_BYTES = "2048";
    try {
      const tightApp = createTestApp({ devModeNoAuth: true });
      setActiveSigner(testKey.signer);

      // 10 KiB of JSON padding — comfortably above the 2 KiB cap.
      const oversize = "x".repeat(10 * 1024);
      const body = JSON.stringify({ ...VALID_ISSUE_REQUEST, _padding: oversize });

      const res = await tightApp.request("/credentials/issue", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": String(Buffer.byteLength(body)),
        },
        body,
      });

      expect(res.status).toBe(413);
      const json = (await res.json()) as { error: { code: string } };
      expect(json.error.code).toBe("PAYLOAD_TOO_LARGE");
    } finally {
      if (prev === undefined) delete process.env.OPENCRED_MAX_BODY_BYTES;
      else process.env.OPENCRED_MAX_BODY_BYTES = prev;
    }
  });

  it("batch endpoint allows bodies larger than the general cap (uses batch cap)", async () => {
    // General cap tight, batch cap generous. A body that would have been
    // rejected by the general cap is accepted on the batch route.
    const prevGeneral = process.env.OPENCRED_MAX_BODY_BYTES;
    const prevBatch = process.env.OPENCRED_MAX_BATCH_BODY_BYTES;
    const prevSecret = process.env.OPENCRED_WEBHOOK_SECRET;
    process.env.OPENCRED_MAX_BODY_BYTES = "2048";
    process.env.OPENCRED_MAX_BATCH_BODY_BYTES = String(10 * 1024 * 1024); // 10 MiB
    delete process.env.OPENCRED_WEBHOOK_SECRET; // no webhookUrl in the body, so secret is irrelevant
    try {
      const splitApp = createTestApp({ devModeNoAuth: true });
      setActiveSigner(testKey.signer);

      // 10 KiB CSV — bigger than general cap but well within batch cap.
      const header = "name,role,validFrom\n";
      const rows = Array.from(
        { length: 300 },
        (_, i) => `Alice${i},Medical Practitioner,2025-06-01T00:00:00Z\n`,
      );
      const csvContent = header + rows.join("");
      const body = JSON.stringify({
        csvContent,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
      });

      const res = await splitApp.request("/credentials/batch", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": String(Buffer.byteLength(body)),
        },
        body,
      });

      expect(res.status).toBe(202);
    } finally {
      if (prevGeneral === undefined) delete process.env.OPENCRED_MAX_BODY_BYTES;
      else process.env.OPENCRED_MAX_BODY_BYTES = prevGeneral;
      if (prevBatch === undefined) delete process.env.OPENCRED_MAX_BATCH_BODY_BYTES;
      else process.env.OPENCRED_MAX_BATCH_BODY_BYTES = prevBatch;
      if (prevSecret !== undefined) process.env.OPENCRED_WEBHOOK_SECRET = prevSecret;
    }
  });
});

// ---------------------------------------------------------------------------
// LOW-04: Dedicated webhook secret
// ---------------------------------------------------------------------------

describe("webhook secret requirement (LOW-04)", () => {
  it("rejects webhookUrl when OPENCRED_WEBHOOK_SECRET is unset (400 WEBHOOK_SECRET_REQUIRED)", async () => {
    const prev = process.env.OPENCRED_WEBHOOK_SECRET;
    delete process.env.OPENCRED_WEBHOOK_SECRET;
    try {
      const noSecretApp = createTestApp({ devModeNoAuth: true });
      setActiveSigner(testKey.signer);

      const res = await noSecretApp.request("/credentials/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          csvContent: "name,role,validFrom\nAlice,Medical Practitioner,2025-06-01T00:00:00Z\n",
          schemaId: "functional-identity/v1",
          issuerDid: testKey.signer.id.split("#")[0],
          validFrom: "2025-06-01T00:00:00Z",
          webhookUrl: "https://example.com/webhook",
        }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: { code: string } };
      expect(body.error.code).toBe("WEBHOOK_SECRET_REQUIRED");
    } finally {
      if (prev !== undefined) process.env.OPENCRED_WEBHOOK_SECRET = prev;
    }
  });

  it("allows batch without webhookUrl regardless of secret config", async () => {
    const prev = process.env.OPENCRED_WEBHOOK_SECRET;
    delete process.env.OPENCRED_WEBHOOK_SECRET;
    try {
      const noSecretApp = createTestApp({ devModeNoAuth: true });
      setActiveSigner(testKey.signer);

      const res = await noSecretApp.request("/credentials/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          csvContent: "name,role,validFrom\nAlice,Medical Practitioner,2025-06-01T00:00:00Z\n",
          schemaId: "functional-identity/v1",
          issuerDid: testKey.signer.id.split("#")[0],
          validFrom: "2025-06-01T00:00:00Z",
          // no webhookUrl — batch runs regardless of webhook secret
        }),
      });

      expect(res.status).toBe(202);
    } finally {
      if (prev !== undefined) process.env.OPENCRED_WEBHOOK_SECRET = prev;
    }
  });
});

// ---------------------------------------------------------------------------
// 404
// ---------------------------------------------------------------------------

describe("404 handler", () => {
  it("returns 404 for unknown endpoints", async () => {
    const res = await app.request("/nonexistent");
    expect(res.status).toBe(404);

    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("NOT_FOUND");
  });
});
