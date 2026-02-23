import { describe, it, expect, vi, beforeAll } from "vitest";
import { Hono } from "hono";
import { X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createVerifyRoutes } from "../routes/verify.js";
import { TrustStore, validateDscChain } from "../dsc-chain.js";
import { errorHandler } from "../middleware/error-handler.js";
import { rateLimitMiddleware } from "../middleware/rate-limit.js";
import { makeTestLogger } from "./helpers.js";

const logger = makeTestLogger();

// --- Test X.509 certificate generation helpers ---
// Uses execFileSync with explicit argument arrays (no shell injection risk).
// All inputs are hardcoded test values, never user-supplied.
// These are ephemeral test certificates generated at runtime, not real credentials.

interface TestCertPair {
  certPem: string;
  keyPem: string;
  cert: X509Certificate;
}

function generateSelfSignedCA(subject: string, days: number = 3650): TestCertPair {
  const dir = mkdtempSync(join(tmpdir(), "opencred-test-"));
  const keyPath = join(dir, "ca.key");
  const certPath = join(dir, "ca.crt");

  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      String(days),
      "-nodes",
      "-subj",
      subject,
    ],
    { stdio: "pipe" },
  );

  const keyPem = readFileSync(keyPath, "utf-8");
  const certPem = readFileSync(certPath, "utf-8");
  return { certPem, keyPem, cert: new X509Certificate(certPem) };
}

function generateSignedCert(
  caKeyPem: string,
  caCertPem: string,
  subject: string,
  options: { days?: number; isCA?: boolean } = {},
): TestCertPair {
  const { days = 365, isCA = false } = options;
  const dir = mkdtempSync(join(tmpdir(), "opencred-test-"));
  const keyPath = join(dir, "leaf.key");
  const csrPath = join(dir, "leaf.csr");
  const certPath = join(dir, "leaf.crt");
  const caKeyPath = join(dir, "ca.key");
  const caCertPath = join(dir, "ca.crt");

  writeFileSync(caKeyPath, caKeyPem);
  writeFileSync(caCertPath, caCertPem);

  execFileSync(
    "openssl",
    [
      "req",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-keyout",
      keyPath,
      "-out",
      csrPath,
      "-nodes",
      "-subj",
      subject,
    ],
    { stdio: "pipe" },
  );

  const signArgs = [
    "x509",
    "-req",
    "-in",
    csrPath,
    "-CA",
    caCertPath,
    "-CAkey",
    caKeyPath,
    "-CAcreateserial",
    "-out",
    certPath,
    "-days",
    String(days),
  ];

  if (isCA) {
    const extPath = join(dir, "ext.cnf");
    writeFileSync(
      extPath,
      "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
    );
    signArgs.push("-extfile", extPath);
  }

  execFileSync("openssl", signArgs, { stdio: "pipe" });

  const keyPem = readFileSync(keyPath, "utf-8");
  const certPem = readFileSync(certPath, "utf-8");
  return { certPem, keyPem, cert: new X509Certificate(certPem) };
}

// --- Response types ---

interface VerifyResponseBody {
  status: string;
  checks: {
    signature: { passed: boolean; detail?: string };
    expiry: { passed: boolean; detail?: string };
    revocation: { passed: boolean; detail?: string };
    dscChain?: { passed: boolean; detail?: string };
  };
}

interface ErrorBody {
  error: { code: string; message: string };
}

// --- Test app factory ---

function createTestApp(
  deps: {
    trustStore?: TrustStore;
    rateLimit?: { windowMs: number; maxRequests: number };
  } = {},
) {
  const app = new Hono();

  if (deps.rateLimit) {
    app.use("/*", rateLimitMiddleware(deps.rateLimit));
  }

  app.route(
    "/verify",
    createVerifyRoutes({
      trustStore: deps.trustStore,
    }),
  );
  app.onError(errorHandler(logger));
  return app;
}

// --- Test certificates (generated once) ---

let cscaCert: TestCertPair;
let dscCert: TestCertPair;
let wrongCsca: TestCertPair;
let shortLivedCsca: TestCertPair;
let trustStoreDir: string;

beforeAll(() => {
  cscaCert = generateSelfSignedCA("/C=NF/O=Test CSCA/CN=Test Country Signing CA");

  dscCert = generateSignedCert(
    cscaCert.keyPem,
    cscaCert.certPem,
    "/C=NF/O=Test DSC/CN=Test Document Signer",
  );

  wrongCsca = generateSelfSignedCA("/C=XX/O=Wrong CSCA/CN=Wrong Country Signing CA");

  // Short-lived cert (1 day) — we simulate expiry by passing a future "now" date
  shortLivedCsca = generateSelfSignedCA("/C=NF/O=Short CSCA/CN=Short Lived CA", 1);

  trustStoreDir = mkdtempSync(join(tmpdir(), "opencred-trust-store-"));
  writeFileSync(join(trustStoreDir, "csca.pem"), cscaCert.certPem);
});

// ======================
// POST /verify endpoint tests
// ======================

describe("POST /verify", () => {
  describe("input validation", () => {
    it("returns 400 for missing credential", async () => {
      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for empty string credential", async () => {
      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: "" }),
      });
      expect(res.status).toBe(400);
    });

    it("returns error for invalid JSON body", async () => {
      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "not json",
      });
      expect(res.status).toBeGreaterThanOrEqual(400);
    });

    it("accepts object credential", async () => {
      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: { proof: {}, type: ["VerifiableCredential"] } }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBeDefined();
    });

    it("accepts string credential", async () => {
      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: "header.payload.signature" }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBeDefined();
    });
  });

  describe("no auth required", () => {
    it("responds without Authorization header", async () => {
      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: { proof: {}, type: ["VerifiableCredential"] } }),
      });
      expect(res.status).not.toBe(401);
      expect(res.status).not.toBe(403);
      expect(res.status).toBe(200);
    });
  });

  describe("result code: VALID", () => {
    it("returns VALID for a correctly signed credential", async () => {
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "VALID",
        verified: true,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("VALID");
      expect(body.checks.signature.passed).toBe(true);
      expect(body.checks.expiry.passed).toBe(true);
      expect(body.checks.revocation.passed).toBe(true);
      expect(body.checks.dscChain).toBeUndefined();

      spy.mockRestore();
    });
  });

  describe("result code: EXPIRED", () => {
    it("returns EXPIRED for an expired credential", async () => {
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "EXPIRED",
        verified: false,
        checks: [
          { name: "signature", passed: true },
          {
            name: "date",
            passed: false,
            detail: "Credential expired (validUntil: 2021-01-01T00:00:00Z)",
          },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("EXPIRED");
      expect(body.checks.signature.passed).toBe(true);
      expect(body.checks.expiry.passed).toBe(false);
      expect(body.checks.expiry.detail).toContain("expired");

      spy.mockRestore();
    });
  });

  describe("result code: INVALID", () => {
    it("returns INVALID for a tampered credential", async () => {
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "INVALID",
        verified: false,
        checks: [{ name: "signature", passed: false, detail: "Signature verification failed" }],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("INVALID");
      expect(body.checks.signature.passed).toBe(false);

      spy.mockRestore();
    });
  });

  describe("result code: UNRESOLVABLE", () => {
    it("returns UNRESOLVABLE when DID cannot be resolved", async () => {
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "UNRESOLVABLE",
        verified: false,
        checks: [
          {
            name: "signature",
            passed: false,
            detail: "Unable to resolve public key from verificationMethod",
          },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("UNRESOLVABLE");
      expect(body.checks.signature.passed).toBe(false);

      spy.mockRestore();
    });
  });

  describe("result code: REVOKED", () => {
    it("returns REVOKED when revocation check fails", async () => {
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "REVOKED",
        verified: false,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
          {
            name: "revocation",
            passed: false,
            detail: "Credential revoked at 2026-06-01T00:00:00Z",
          },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("REVOKED");
      expect(body.checks.signature.passed).toBe(true);
      expect(body.checks.revocation.passed).toBe(false);
      expect(body.checks.revocation.detail).toContain("revoked");

      spy.mockRestore();
    });
  });

  describe("DSC/CSCA chain validation via API", () => {
    it("includes dscChain check when dscCertificateChain is provided", async () => {
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "VALID",
        verified: true,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
        ],
      });

      const trustStore = TrustStore.fromCertificates([cscaCert.cert]);
      const app = createTestApp({ trustStore });

      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
          dscCertificateChain: [dscCert.certPem],
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("VALID");
      expect(body.checks.dscChain).toBeDefined();
      expect(body.checks.dscChain!.passed).toBe(true);

      spy.mockRestore();
    });

    it("returns INVALID when DSC chain fails but credential is valid", async () => {
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "VALID",
        verified: true,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
        ],
      });

      const trustStore = TrustStore.fromCertificates([wrongCsca.cert]);
      const app = createTestApp({ trustStore });

      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
          dscCertificateChain: [dscCert.certPem],
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("INVALID");
      expect(body.checks.dscChain!.passed).toBe(false);
      expect(body.checks.dscChain!.detail).toContain("not issued by any trusted CSCA");

      spy.mockRestore();
    });

    it("fails dscChain when no trust store is configured", async () => {
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "VALID",
        verified: true,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
        ],
      });

      const app = createTestApp();

      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
          dscCertificateChain: [dscCert.certPem],
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("INVALID");
      expect(body.checks.dscChain!.passed).toBe(false);
      expect(body.checks.dscChain!.detail).toContain("No trusted CSCA");

      spy.mockRestore();
    });

    it("omits dscChain when no dscCertificateChain provided", async () => {
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "VALID",
        verified: true,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
        ],
      });

      const trustStore = TrustStore.fromCertificates([cscaCert.cert]);
      const app = createTestApp({ trustStore });

      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("VALID");
      expect(body.checks.dscChain).toBeUndefined();

      spy.mockRestore();
    });
  });

  describe("rate limiting", () => {
    it("returns 429 when rate limit is exceeded", async () => {
      const app = createTestApp({
        rateLimit: { windowMs: 60_000, maxRequests: 2 },
      });

      const mockVerify = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      mockVerify.mockResolvedValue({
        code: "VALID",
        verified: true,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
        ],
      });

      const payload = JSON.stringify({
        credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
      });

      const res1 = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      });
      expect(res1.status).toBe(200);

      const res2 = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      });
      expect(res2.status).toBe(200);

      const res3 = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      });
      expect(res3.status).toBe(429);
      const body = (await res3.json()) as ErrorBody;
      expect(body.error.code).toBe("RATE_LIMIT_EXCEEDED");

      mockVerify.mockRestore();
    });
  });

  describe("response format", () => {
    it("returns correctly structured response with all check fields", async () => {
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "VALID",
        verified: true,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
          { name: "revocation", passed: true },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: { proof: { type: "DataIntegrityProof" }, type: ["VerifiableCredential"] },
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;

      expect(body).toHaveProperty("status");
      expect(body).toHaveProperty("checks");
      expect(body.checks).toHaveProperty("signature");
      expect(body.checks).toHaveProperty("expiry");
      expect(body.checks).toHaveProperty("revocation");
      expect(body.checks.signature).toHaveProperty("passed");
      expect(body.checks.expiry).toHaveProperty("passed");
      expect(body.checks.revocation).toHaveProperty("passed");

      spy.mockRestore();
    });
  });
});

// ======================
// DSC/CSCA chain validation unit tests
// ======================

describe("TrustStore", () => {
  it("loads certificates from a directory", () => {
    const store = TrustStore.load(trustStoreDir);
    expect(store.size).toBe(1);
  });

  it("handles non-existent directory gracefully", () => {
    const store = TrustStore.load("/nonexistent/path", logger);
    expect(store.size).toBe(0);
  });

  it("ignores non-PEM files", () => {
    const dir = mkdtempSync(join(tmpdir(), "opencred-test-"));
    writeFileSync(join(dir, "readme.txt"), "not a cert");
    writeFileSync(join(dir, "data.json"), "{}");
    const store = TrustStore.load(dir, logger);
    expect(store.size).toBe(0);
  });

  it("skips invalid certificate files", () => {
    const dir = mkdtempSync(join(tmpdir(), "opencred-test-"));
    writeFileSync(join(dir, "bad.pem"), "not a valid PEM cert");
    writeFileSync(join(dir, "good.pem"), cscaCert.certPem);
    const store = TrustStore.load(dir, logger);
    expect(store.size).toBe(1);
  });

  it("creates store from certificates directly", () => {
    const store = TrustStore.fromCertificates([cscaCert.cert]);
    expect(store.size).toBe(1);
  });

  it("finds issuer for a certificate", () => {
    const store = TrustStore.fromCertificates([cscaCert.cert]);
    const issuer = store.findIssuer(dscCert.cert);
    expect(issuer).toBeDefined();
  });

  it("returns undefined when no issuer matches", () => {
    const store = TrustStore.fromCertificates([wrongCsca.cert]);
    const issuer = store.findIssuer(dscCert.cert);
    expect(issuer).toBeUndefined();
  });
});

describe("validateDscChain", () => {
  it("validates a correct DSC -> CSCA chain", () => {
    const store = TrustStore.fromCertificates([cscaCert.cert]);
    const result = validateDscChain([dscCert.certPem], store);
    expect(result.passed).toBe(true);
  });

  it("fails for empty certificate chain", () => {
    const store = TrustStore.fromCertificates([cscaCert.cert]);
    const result = validateDscChain([], store);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Empty certificate chain");
  });

  it("fails when trust store is empty", () => {
    const store = TrustStore.fromCertificates([]);
    const result = validateDscChain([dscCert.certPem], store);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("No trusted CSCA");
  });

  it("fails for a chain root not issued by trusted CSCA (wrong issuer)", () => {
    const store = TrustStore.fromCertificates([wrongCsca.cert]);
    const result = validateDscChain([dscCert.certPem], store);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("not issued by any trusted CSCA");
  });

  it("fails for an expired certificate in the chain", () => {
    // Use the short-lived cert and simulate a future date beyond its validity
    const store = TrustStore.fromCertificates([shortLivedCsca.cert]);
    const futureDate = new Date();
    futureDate.setFullYear(futureDate.getFullYear() + 1);
    const result = validateDscChain([shortLivedCsca.certPem], store, futureDate);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("expired");
  });

  it("fails for invalid PEM in chain", () => {
    const store = TrustStore.fromCertificates([cscaCert.cert]);
    const result = validateDscChain(["not-a-valid-cert"], store);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Invalid certificate at position 0");
  });

  it("validates a multi-cert chain (DSC -> intermediate -> CSCA)", () => {
    const intermediateCert = generateSignedCert(
      cscaCert.keyPem,
      cscaCert.certPem,
      "/C=NF/O=Test Intermediate/CN=Test Intermediate CA",
      { isCA: true },
    );

    const leafCert = generateSignedCert(
      intermediateCert.keyPem,
      intermediateCert.certPem,
      "/C=NF/O=Test Leaf/CN=Test Document Signer Leaf",
    );

    const store = TrustStore.fromCertificates([cscaCert.cert]);
    const result = validateDscChain([leafCert.certPem, intermediateCert.certPem], store);
    expect(result.passed).toBe(true);
  });

  it("fails when intermediate certificate is not a CA", () => {
    // Generate intermediate WITHOUT isCA flag
    const intermediateCert = generateSignedCert(
      cscaCert.keyPem,
      cscaCert.certPem,
      "/C=NF/O=Test Intermediate/CN=Test Non-CA Intermediate",
    );

    const leafCert = generateSignedCert(
      intermediateCert.keyPem,
      intermediateCert.certPem,
      "/C=NF/O=Test Leaf/CN=Test Document Signer Leaf Non-CA",
    );

    const store = TrustStore.fromCertificates([cscaCert.cert]);
    const result = validateDscChain([leafCert.certPem, intermediateCert.certPem], store);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("not a CA certificate");
  });

  it("fails when chain linkage is broken (wrong order)", () => {
    const intermediateCert = generateSignedCert(
      cscaCert.keyPem,
      cscaCert.certPem,
      "/C=NF/O=Test Intermediate/CN=Test Intermediate CA 2",
      { isCA: true },
    );

    const leafCert = generateSignedCert(
      intermediateCert.keyPem,
      intermediateCert.certPem,
      "/C=NF/O=Test Leaf/CN=Test Document Signer Leaf 2",
    );

    const store = TrustStore.fromCertificates([cscaCert.cert]);
    // Wrong order: intermediate first, then leaf (should be leaf first)
    const result = validateDscChain([intermediateCert.certPem, leafCert.certPem], store);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("was not issued by");
  });
});
