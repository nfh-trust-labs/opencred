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

  // ----- PDF-as-input branch ------------------------------------------ //
  // Round-trip: issue with `packageFormats: ["pdf"]`, take the produced
  // PDF bytes, post them straight back to /v1/credentials/verify with
  // Content-Type: application/pdf, expect VALID. The point is to pin the
  // contract between the issuance side (which writes the embedded
  // `OpenCredCredential` info-dict key) and the verification side (which
  // reads it). Breaks if either end stops honoring the key.
  it("verifies a PDF certificate posted with Content-Type: application/pdf", async () => {
    const issueRes = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        credentialSubject: EDUCATION_SUBJECT,
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat: "data-integrity",
        packageFormats: ["pdf"],
      }),
    });
    expect(issueRes.status).toBe(200);
    const issued = (await issueRes.json()) as {
      packagedOutputs?: Array<{ format: string; data: string; encoding: string }>;
    };
    const pdfOutput = issued.packagedOutputs?.find((o) => o.format === "pdf");
    expect(pdfOutput, "issue response did not include a packaged PDF").toBeDefined();
    expect(pdfOutput!.encoding).toBe("base64");
    const pdfBytes = Buffer.from(pdfOutput!.data, "base64");
    expect(pdfBytes.subarray(0, 5).toString("ascii")).toBe("%PDF-");

    const verifyRes = await app.request("/v1/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/pdf" },
      body: pdfBytes,
    });

    expect(verifyRes.status).toBe(200);
    const result = (await verifyRes.json()) as Record<string, unknown>;
    expect(result.valid).toBe(true);
    expect(result.code).toBe("VALID");
  });

  it("returns valid=false with a structured check for a PDF without an embedded credential", async () => {
    // A PDF that's syntactically valid but carries no `OpenCredCredential`
    // info-dict key — the legacy / non-OpenCred case. The route must
    // surface this as a clean 200 INVALID with the
    // `pdf-embedded-credential` check failed, not a 500 or generic error.
    // Built with pdfkit (already a dep here) rather than pulling pdf-lib
    // into apps/server just for this fixture.
    const { default: PDFDocument } = await import("pdfkit");
    const blankBytes: Buffer = await new Promise((resolve, reject) => {
      const doc = new PDFDocument({ size: "A4" });
      const chunks: Buffer[] = [];
      doc.on("data", (chunk: Buffer) => chunks.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);
      doc.text("a plain pdf, not produced by OpenCred");
      doc.end();
    });

    const verifyRes = await app.request("/v1/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/pdf" },
      body: blankBytes,
    });

    expect(verifyRes.status).toBe(200);
    const result = (await verifyRes.json()) as {
      valid: boolean;
      code: string;
      checks: Array<{ name: string; passed: boolean }>;
    };
    expect(result.valid).toBe(false);
    expect(result.code).toBe("INVALID");
    expect(result.checks.some((c) => c.name === "pdf-embedded-credential" && !c.passed)).toBe(true);
  });

  it("verifies a PDF that wraps an sd-jwt-vc compact token", async () => {
    // Round-trip parity check for the compact-token path of the issuance
    // PDF generator. The server's pdf-generator embeds either the
    // PixelPass-compressed VC (data-integrity) or the raw compact token
    // (vc-jwt / sd-jwt-vc) under the `OpenCredCredential` info-dict key.
    // The format dispatcher in `verifyPdf` routes these through
    // `detectCredentialInputFormat`'s `jwt-compact` branch — this test
    // pins that path end-to-end so a regression in the detection rules
    // or the embedding switch in `pdf-generator.ts` is caught.
    const issueRes = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        credentialSubject: EDUCATION_SUBJECT,
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat: "sd-jwt-vc",
        selectiveDisclosureClaims: ["/credentialSubject/role"],
        packageFormats: ["pdf"],
      }),
    });
    expect(issueRes.status).toBe(200);
    const issued = (await issueRes.json()) as {
      packagedOutputs?: Array<{ format: string; data: string; encoding: string }>;
    };
    const pdfOutput = issued.packagedOutputs?.find((o) => o.format === "pdf");
    expect(pdfOutput, "sd-jwt-vc issue did not include a packaged PDF").toBeDefined();
    const pdfBytes = Buffer.from(pdfOutput!.data, "base64");

    const verifyRes = await app.request("/v1/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/pdf" },
      body: pdfBytes,
    });

    expect(verifyRes.status).toBe(200);
    const result = (await verifyRes.json()) as Record<string, unknown>;
    expect(result.valid).toBe(true);
    expect(result.code).toBe("VALID");
  });

  it("falls back to DeDi for did:web resolution when the canonical HTTPS endpoint is unreachable", async () => {
    // End-to-end pin of the #527 contract: a credential whose issuer is a
    // did:web at a deliberately bad domain still verifies VALID when DeDi
    // has the matching DID document. The HTTPS resolution path will fail
    // DNS lookup on a `.invalid` host (RFC 2606), so the DIDWebResolver's
    // fallback is the only way the verify can succeed — proving the verify
    // route correctly threads `createDeDiDIDWebFallback` into the resolver
    // when `getDeDiClient()` is non-null.
    const { generateKeyPairSync } = await import("node:crypto");
    const { signCredential } = await import("@opencred/crypto");
    const { setDeDiClient, resetDeDiClient } = await import("../dedi-singleton.js");

    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const did = "did:web:nonexistent-host-for-smoke-test-12345.invalid";
    const vmId = `${did}#key-0`;
    const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;

    const didDocument = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did,
      verificationMethod: [
        {
          id: vmId,
          type: "JsonWebKey",
          controller: did,
          publicKeyJwk: publicJwk,
        },
      ],
      assertionMethod: [vmId],
    };

    const unsigned = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:dedi-fallback-smoke-test",
      type: ["VerifiableCredential"],
      issuer: did,
      validFrom: "2026-01-01T00:00:00Z",
      credentialSubject: { id: "did:example:holder", name: "Smoke Test Subject" },
    };
    const signedVC = await signCredential(
      unsigned,
      { id: vmId, privateKey, publicKey, algorithm: "P-256" },
      { verificationMethod: vmId, proofPurpose: "assertionMethod" },
    );

    // Stub DeDi client: `resolveDID` powers the fallback we're testing.
    // `queryRevocationHash` is also stubbed because the verifier runs a
    // revocation check whenever DeDi is configured — without it the
    // overall result code becomes UNRESOLVABLE even though the signature
    // verifies. The "not revoked" branch is the realistic happy path
    // (record absent → credential not in the revocation registry).
    let resolveDidCalls = 0;
    const stubDeDiClient = {
      resolveDID: async (inputDid: string) => {
        resolveDidCalls += 1;
        if (inputDid !== did) {
          throw new Error("record not found");
        }
        return {
          did: inputDid,
          document: didDocument,
          keyStatus: "current" as const,
        };
      },
      queryRevocationHash: async () => ({ revoked: false as const }),
    } as unknown as Parameters<typeof setDeDiClient>[0];

    try {
      setDeDiClient(stubDeDiClient);

      const verifyRes = await app.request("/v1/credentials/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: JSON.stringify(signedVC) }),
      });

      expect(verifyRes.status).toBe(200);
      const result = (await verifyRes.json()) as Record<string, unknown>;
      expect(result.valid).toBe(true);
      expect(result.code).toBe("VALID");
      // Pin that the fallback actually got called — without this, an
      // accidental change that wires `new DIDWebResolver()` (no fallback)
      // would still pass the test for the wrong reason (DNS failure
      // dropped, document magically resolved somehow).
      expect(resolveDidCalls).toBeGreaterThanOrEqual(1);
    } finally {
      resetDeDiClient();
    }
  });

  it("returns 400 BAD_REQUEST when application/pdf body is not actually a PDF", async () => {
    const verifyRes = await app.request("/v1/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/pdf" },
      body: Buffer.from("not a pdf at all"),
    });

    expect(verifyRes.status).toBe(400);
    const body = (await verifyRes.json()) as { error: { code: string } };
    expect(body.error.code).toBe("BAD_REQUEST");
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

  // Anand's P3-03: PEM scan used to regex-match the entire body, including
  // `csvContent` up to 200 MiB, blocking the event loop for tens of ms per
  // batch request. Scan is now truncated to the first 4 KiB of long
  // strings. Both assertions below verify the truncation preserves the
  // realistic-attack coverage (PEM header near the top) without the
  // unnecessary full-body scan.

  it("POST /v1/credentials/batch still catches a PEM header in the first 4 KiB of csvContent (P3-03)", async () => {
    // Header + a PEM-containing row at the top, then a large tail of
    // benign content that pre-P3-03 would have been scanned redundantly.
    const bigTail = "x,".repeat(100_000); // ~200 KB of benign content
    const csv = `name,email,notes\nMallory,m@example.com,"${sec1Pem.replace(/\n/g, " ")}"\n${bigTail}\n`;
    const res = await app.request("/v1/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent: csv,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-15T00:00:00Z",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.message).toMatch(/PEM-encoded private key/);
  });

  it("rejectKeyMaterial does not detect a PEM header past the 4 KiB scan window (P3-03)", async () => {
    // Pre-P3-03 the scan covered the full string. After the fix a PEM
    // header buried past the 4 KiB mark is intentionally NOT flagged: the
    // PEM `-----BEGIN ... PRIVATE KEY-----` marker always lives at the
    // start of a real key blob, so "pasted somewhere in the middle of a
    // 200 MiB CSV" is not a realistic attack. This test locks the window
    // in so a future regression toward full-body scanning (or 200 KB
    // scans) is caught.
    const pad = "x".repeat(5_000); // 5 KB of benign content before the PEM block
    const res = await app.request("/v1/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credential: {
          id: "urn:test:1",
          notes: `${pad}${sec1Pem}`,
        },
      }),
    });
    expect(res.status).not.toBe(400);
  });
});
