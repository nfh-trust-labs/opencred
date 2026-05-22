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
import {
  sanitizeChecksForServerResponse,
  buildVerifyResponseBody,
  resolveCanonicalRevocationRegistryUrl,
} from "../routes/credentials.js";
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

  // Regression: a mis-templated request body (e.g. wrapping a JSON object
  // inside string quotes so the inner `"` closes the outer string early)
  // caused `c.req.json()` to throw a SyntaxError, and the global error
  // handler returned a generic 500 INTERNAL_ERROR — indistinguishable
  // from a real server fault. Map malformed bodies to 400 INVALID_JSON
  // so the caller can recognise the parser-level problem.
  it("returns 400 INVALID_JSON when request body is malformed JSON", async () => {
    // Inner unescaped `"` after the property value — produces the
    // "Expected ',' or '}' after property value" SyntaxError shape.
    const malformedBody = '{"credential":"{"@context":"https://example.org"}"}';

    const verifyRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: malformedBody,
    });

    expect(verifyRes.status).toBe(400);
    const body = (await verifyRes.json()) as { error?: { code?: string; message?: string } };
    expect(body.error?.code).toBe("INVALID_JSON");
    expect(body.error?.message).toMatch(/Request body is not valid JSON/i);
  });

  // The 400 message must surface the V8/JSC parser's positional hint so a
  // bootcamp attendee can paste a long body into a tool and jump to the
  // failing offset. This locks the contract that `parseJsonBody` does NOT
  // strip the parser's own description on its way to the wire.
  it("INVALID_JSON 400 message includes parser position info", async () => {
    const malformedBody = '{"credential":"{"@context":"https://example.org"}"}';

    const verifyRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: malformedBody,
    });

    expect(verifyRes.status).toBe(400);
    const body = (await verifyRes.json()) as { error?: { code?: string; message?: string } };
    expect(body.error?.code).toBe("INVALID_JSON");
    expect(body.error?.message).toMatch(/at position \d+/i);
  });

  // Regression guard: the OLD heuristic-based detector classified ANY
  // SyntaxError as a malformed body when its stack mentioned Hono internals.
  // The route-level wrapper is narrower — a SyntaxError thrown DEEPER in a
  // handler (e.g. the verify route's inner `JSON.parse(parsed.credential)`
  // for `format === "json"` input) must NOT be re-classified as
  // INVALID_JSON. The outer body here is valid JSON; the `credential` field
  // value is not.
  it("does not re-classify a SyntaxError thrown inside the handler as INVALID_JSON", async () => {
    const requestBody = JSON.stringify({ credential: "{not valid json" });

    const verifyRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: requestBody,
    });

    // The exact status depends on which guard catches first (format
    // detection sees an unrecognized shape, or the JSON.parse inside the
    // handler throws and falls through to 500 INTERNAL_ERROR). The
    // assertion is strictly the no-misclassification contract: whatever
    // the response is, it must NOT be a 400 INVALID_JSON.
    if (verifyRes.status === 400) {
      const body = (await verifyRes.json()) as { error?: { code?: string } };
      expect(body.error?.code).not.toBe("INVALID_JSON");
    } else {
      // Anything other than 400 is fine — by definition it can't be the
      // INVALID_JSON code we are guarding against.
      expect(verifyRes.status).not.toBe(400);
    }
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
// resolveCanonicalRevocationRegistryUrl — issue #528
// ---------------------------------------------------------------------------

describe("resolveCanonicalRevocationRegistryUrl (#528)", () => {
  // The canonical DeDi lookup URL is what gets serialized into every issued
  // credential's `credentialStatus.id` + `statusListCredential`. A third-party
  // W3C-compliant verifier dereferences that URL, so it MUST resolve. The
  // resolver accepts three input shapes (bare base, canonical query, canonical
  // lookup) and the tests below pin each shape to a well-formed output.
  const NS = "issuer-default";
  const REG = "vc-revocation-registry";

  it("derives the canonical lookup URL from a bare-base input + configured namespace", () => {
    const out = resolveCanonicalRevocationRegistryUrl("https://my-dedi.example.org", {
      OPENCRED_DEDI_NAMESPACE: NS,
    });
    expect(out).toBe(`https://my-dedi.example.org/dedi/lookup/${NS}/${REG}`);
  });

  it("strips a single trailing slash on the bare-base input (no double slash in the output)", () => {
    const out = resolveCanonicalRevocationRegistryUrl("https://my-dedi.example.org/", {
      OPENCRED_DEDI_NAMESPACE: NS,
    });
    expect(out).toBe(`https://my-dedi.example.org/dedi/lookup/${NS}/${REG}`);
    expect(out.includes("//dedi/")).toBe(false);
  });

  it("strips multiple trailing slashes on the bare-base input", () => {
    const out = resolveCanonicalRevocationRegistryUrl("https://my-dedi.example.org///", {
      OPENCRED_DEDI_NAMESPACE: NS,
    });
    expect(out).toBe(`https://my-dedi.example.org/dedi/lookup/${NS}/${REG}`);
  });

  it("preserves an API-gateway path prefix on a bare-base URL (and appends /dedi/lookup/...)", () => {
    // Some operators front DeDi behind a gateway mount such as `/api/v1`.
    // We respect that prefix rather than overwriting it.
    const out = resolveCanonicalRevocationRegistryUrl("https://my-dedi.example.org/api/v1", {
      OPENCRED_DEDI_NAMESPACE: NS,
    });
    expect(out).toBe(`https://my-dedi.example.org/api/v1/dedi/lookup/${NS}/${REG}`);
  });

  it("returns a canonical /dedi/lookup/ URL unchanged", () => {
    const canonical = `https://my-dedi.example.org/dedi/lookup/${NS}/${REG}`;
    const out = resolveCanonicalRevocationRegistryUrl(canonical, {
      OPENCRED_DEDI_NAMESPACE: NS,
    });
    expect(out).toBe(canonical);
  });

  it("strips a trailing slash on a canonical /dedi/lookup/ URL", () => {
    const canonical = `https://my-dedi.example.org/dedi/lookup/${NS}/${REG}`;
    const out = resolveCanonicalRevocationRegistryUrl(`${canonical}/`, {
      OPENCRED_DEDI_NAMESPACE: NS,
    });
    expect(out).toBe(canonical);
  });

  it("rewrites legacy /dedi/query/ → /dedi/lookup/ (back-compat with pre-v1.3.0 bootcamp wording)", () => {
    const queryUrl = `https://my-dedi.example.org/dedi/query/${NS}/${REG}`;
    const out = resolveCanonicalRevocationRegistryUrl(queryUrl, {
      OPENCRED_DEDI_NAMESPACE: NS,
    });
    expect(out).toBe(`https://my-dedi.example.org/dedi/lookup/${NS}/${REG}`);
  });

  it("rewrites /dedi/query/ even when the caller's namespace differs from configured (caller's URL wins)", () => {
    // The canonical-shape URL already encodes a namespace; we don't second-
    // guess it with the configured default. This matters when a single
    // server issues against multiple namespaces.
    const queryUrl =
      "https://my-dedi.example.org/dedi/query/other-namespace/vc-revocation-registry";
    const out = resolveCanonicalRevocationRegistryUrl(queryUrl, {
      OPENCRED_DEDI_NAMESPACE: NS,
    });
    expect(out).toBe(
      "https://my-dedi.example.org/dedi/lookup/other-namespace/vc-revocation-registry",
    );
  });

  it("throws ValidationError on a bare-base input when OPENCRED_DEDI_NAMESPACE is unset", () => {
    expect(() => resolveCanonicalRevocationRegistryUrl("https://my-dedi.example.org", {})).toThrow(
      /OPENCRED_DEDI_NAMESPACE/,
    );
  });

  it("throws ValidationError on a bare-base input when OPENCRED_DEDI_NAMESPACE is the empty string", () => {
    expect(() =>
      resolveCanonicalRevocationRegistryUrl("https://my-dedi.example.org", {
        OPENCRED_DEDI_NAMESPACE: "",
      }),
    ).toThrow(/OPENCRED_DEDI_NAMESPACE/);
  });

  it("does NOT throw on a canonical-shape input when namespace is unset (URL is self-contained)", () => {
    const canonical = `https://my-dedi.example.org/dedi/lookup/${NS}/${REG}`;
    expect(() => resolveCanonicalRevocationRegistryUrl(canonical, {})).not.toThrow();
  });

  it("the canonical id and statusListCredential round-trip through path components a W3C verifier expects", () => {
    // Sanity: when the helper feeds `credentialStatus.id = <out>/<hash>` and
    // `statusListCredential = <out>`, both URLs share the same `/dedi/lookup/`
    // prefix and the namespace and registry name appear in path-position 4/5
    // (the shape `gh issue #528` asks for).
    const out = resolveCanonicalRevocationRegistryUrl("https://my-dedi.example.org", {
      OPENCRED_DEDI_NAMESPACE: NS,
    });
    const url = new URL(out);
    const segments = url.pathname.split("/").filter(Boolean);
    expect(segments).toEqual(["dedi", "lookup", NS, REG]);
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
      publishRevocationHash: async () => ({ revoked: true as const, revokedAt }),
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
      publishRevocationHash: async () => ({ revoked: true as const, revokedAt }),
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

  it("returns 409 DEDI_RECORD_EXISTS with hint when the hash is already revoked", async () => {
    // The dedi-client adapter rewraps DeDi's "duplicate record name" 409 as
    // DeDiRecordExistsError so re-running revoke (after a container restart,
    // for example) surfaces an actionable response rather than the opaque
    // DEDI_CLIENT_ERROR users hit during the 2026-05-21 bootcamp dry-run.
    // See docs/bootcamp/post-bootcamp-followups.md §6.
    const { DeDiRecordExistsError } = await import("@opencred/shared");
    const mockClient = {
      publishRevocationHash: async () => {
        throw new DeDiRecordExistsError(
          "This hash is already in the revocation registry",
          "Use POST /v1/credentials/revocation-status to confirm the prior revoke landed",
          { message: "duplicate record name" },
        );
      },
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/credentials/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash: "a".repeat(64) }),
    });
    expect(res.status).toBe(409);
    const body = (await res.json()) as {
      error: { code: string; message: string; hint: string; statusCode: number };
    };
    expect(body.error.code).toBe("DEDI_RECORD_EXISTS");
    expect(body.error.hint).toContain("revocation-status");
    expect(body.error.statusCode).toBe(409);
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
      queryRevocationHash: async () => ({ revoked: false as const }),
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
// Packaging compact-token credentials (vc-jwt / sd-jwt-vc)
// ---------------------------------------------------------------------------
//
// `/credentials/package` accepts the credential as either a JSON object
// (data-integrity) or a compact token string (vc-jwt, sd-jwt-vc). For a
// caller using `proofFormat: "sd-jwt-vc"` the issue endpoint returns a
// `~`-separated compact string that this endpoint must accept directly
// (otherwise the only path to a printable PDF is to re-issue in another
// format). The packager:
//   - decodes the JWT payload offline (no signature check) to drive the PDF
//     layout;
//   - embeds the raw compact token verbatim in the QR (so any verifier
//     scanning the QR runs a real cryptographic check);
//   - wraps the token in a `{ format, credential }` envelope for JSON.

describe("POST /credentials/package — compact-token input", () => {
  // Use sd-jwt-vc to obtain a real compact token. The vc-jwt proof format
  // returns a JSON-LD VC with the JWT embedded as `proof.jwt` (i.e. an
  // object), not a compact string — so the compact-token packaging path
  // is exercised via sd-jwt-vc which always returns a `~`-separated
  // compact string.
  async function issueSdJwtVc(): Promise<string> {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        issuerDid: testKey.signer.id.split("#")[0],
        proofFormat: "sd-jwt-vc",
        selectiveDisclosureClaims: ["/credentialSubject/role"],
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { credential: string; isCompactToken: boolean };
    expect(body.isCompactToken).toBe(true);
    expect(typeof body.credential).toBe("string");
    return body.credential;
  }

  it("accepts an sd-jwt-vc compact token and returns json + qr-svg + pdf", async () => {
    const token = await issueSdJwtVc();

    const res = await app.request("/credentials/package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: token,
        formats: ["json", "qr-svg", "qr-png", "pdf"],
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      outputs: Array<{
        format: string;
        data: string;
        mimeType: string;
        encoding: string;
        suggestedFileName: string;
      }>;
      errors: unknown[];
    };
    expect(body.errors).toEqual([]);
    expect(body.outputs.map((o) => o.format).sort()).toEqual(
      ["json", "pdf", "qr-png", "qr-svg"].sort(),
    );

    // JSON envelope must wrap the original token verbatim, not the decoded payload.
    const jsonOutput = body.outputs.find((o) => o.format === "json");
    expect(jsonOutput).toBeDefined();
    const wrapper = JSON.parse(jsonOutput!.data) as { format: string; credential: string };
    expect(wrapper.format).toBe("sd-jwt-vc");
    expect(wrapper.credential).toBe(token);

    // QR SVG must contain the raw token (no PixelPass `OPENCRED1:`
    // wrapper) so a generic QR scanner sees the same JWT a verifier
    // would consume.
    const svgOutput = body.outputs.find((o) => o.format === "qr-svg");
    expect(svgOutput).toBeDefined();
    expect(svgOutput!.data).toContain("<svg");
    // The raw JWT shouldn't appear textually in the SVG (it's encoded as
    // QR pixels), but the PixelPass header *would* be present if we
    // were going through that pipeline. Asserting it isn't is enough.
    expect(svgOutput!.data).not.toContain("OPENCRED1:");

    // PDF comes back base64-encoded with the application/pdf mime type.
    const pdfOutput = body.outputs.find((o) => o.format === "pdf");
    expect(pdfOutput).toBeDefined();
    expect(pdfOutput!.encoding).toBe("base64");
    expect(pdfOutput!.mimeType).toBe("application/pdf");
    const pdfBytes = Buffer.from(pdfOutput!.data, "base64");
    // PDF magic number: `%PDF`
    expect(pdfBytes.subarray(0, 4).toString()).toBe("%PDF");
  });

  it("rejects an empty string credential with 400", async () => {
    const res = await app.request("/credentials/package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: "", formats: ["json"] }),
    });
    expect(res.status).toBe(400);
  });

  it("rejects a non-JWT, non-object credential string with a deterministic 400", async () => {
    // ValidationError from `decode-for-display.ts:235-238` (the dot-count guard)
    // bubbles to the route, which the global error handler renders as a 400
    // via `OpenCredError.toJSON()`. We assert the exact status and the stable
    // error code — accepting 500 here would hide a regression that drops the
    // dot-count check.
    const res = await app.request("/credentials/package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: "this-is-just-a-plain-string-with-no-dots-or-tildes",
        formats: ["json"],
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error?: { code?: string; message?: string } };
    expect(body.error?.code).toBe("VALIDATION_ERROR");
    expect(body.error?.message).toMatch(/2 '\.' separators/);
  });

  it("does not trip rejectKeyMaterial when given a legitimate compact token", async () => {
    // Security invariant (CLAUDE.md rule 1) — `rejectKeyMaterial` runs
    // recursively on every POST body and rejects any string field that
    // looks like a PEM-encoded private key. A compact JWT is base64url
    // segments separated by `.` — no `-----BEGIN ...` headers — so the
    // guard must not false-positive. This test pins that contract: if
    // a future refactor decodes string fields before scanning, every
    // compact-token request would silently break, and this test would
    // fail with a 400 BAD_REQUEST instead of a 200.
    const issueRes = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        issuerDid: testKey.signer.id.split("#")[0],
        proofFormat: "sd-jwt-vc",
        selectiveDisclosureClaims: ["/credentialSubject/role"],
      }),
    });
    const issued = (await issueRes.json()) as { credential: string };

    const res = await app.request("/credentials/package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: issued.credential, formats: ["json"] }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { errors: unknown[] };
    expect(body.errors).toEqual([]);
  });

  it("renders a PDF without footer text when customization.footerText is empty", async () => {
    // The empty-string suppression at pdf-generator.ts is the only way
    // for an issuer to opt out of the verification disclaimer footer.
    // Pin the contract by extracting the PDF text and asserting the
    // default footer string is absent. Pdfkit emits text via Tj/TJ
    // operators in the content stream — a substring check on the raw
    // PDF bytes is sufficient (the default is plain ASCII so it would
    // appear verbatim in an unencrypted stream).
    const issueRes = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        issuerDid: testKey.signer.id.split("#")[0],
        proofFormat: "data-integrity",
      }),
    });
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };

    const res = await app.request("/credentials/package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: issued.credential,
        formats: ["pdf"],
        customization: { footerText: "" },
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { outputs: Array<{ format: string; data: string }> };
    const pdfOutput = body.outputs.find((o) => o.format === "pdf");
    expect(pdfOutput).toBeDefined();
    const pdfBytes = Buffer.from(pdfOutput!.data, "base64");
    const pdfText = pdfBytes.toString("latin1");
    expect(pdfText).not.toContain("This credential is digitally signed");
    expect(pdfText).not.toContain("OpenCred Desktop");
  });
});

// ---------------------------------------------------------------------------
// /credentials/issue inline-package for vc-jwt
// ---------------------------------------------------------------------------

describe("POST /credentials/issue — packageFormats with compact-token proofs", () => {
  it("returns packagedOutputs when proofFormat is sd-jwt-vc (compact token)", async () => {
    // Regression: the inline-package branch on /credentials/issue was
    // previously gated by `!isCompactToken`, so a caller issuing with a
    // compact proof format and asking for `packageFormats` got an empty
    // array. After the JWT-aware packager the same call returns a full
    // set of outputs.
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        issuerDid: testKey.signer.id.split("#")[0],
        proofFormat: "sd-jwt-vc",
        selectiveDisclosureClaims: ["/credentialSubject/role"],
        packageFormats: ["pdf", "json"],
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      credential: string;
      isCompactToken: boolean;
      packagedOutputs?: Array<{ format: string; data: string }>;
    };
    expect(body.isCompactToken).toBe(true);
    expect(body.packagedOutputs).toBeDefined();
    expect(body.packagedOutputs!.length).toBe(2);
    const formats = body.packagedOutputs!.map((o) => o.format);
    expect(formats).toContain("pdf");
    expect(formats).toContain("json");
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
