import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import { createBusinessVcOnboardingRoutes, type BusinessVcOnboardingDeps } from "../routes/onboarding.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

vi.mock("@opencred/verification", async () => {
  const actual = await vi.importActual<typeof import("@opencred/verification")>("@opencred/verification");
  return { ...actual, verifyCredential: vi.fn() };
});

vi.mock("@opencred/delegation", async () => {
  const actual = await vi.importActual<typeof import("@opencred/delegation")>("@opencred/delegation");
  return { ...actual, registerDelegation: vi.fn().mockResolvedValue({}) };
});

import { verifyCredential } from "@opencred/verification";

const mockedVerify = vi.mocked(verifyCredential);
const logger = makeTestLogger();
const TEST_JWT_SECRET = "test-jwt-secret-must-be-at-least-32-characters-long";
const TEST_JWT_ISSUER = "opencred-test";
const TEST_JWT_EXPIRY = 3600;
const TEST_JWT_KEY = new TextEncoder().encode(TEST_JWT_SECRET);
const TEST_OPENCRED_DID = "did:key:z6MktestedOpencredKey123456";

function makeOversizedVcJwt() {
  const header = { alg: "ES256", typ: "JWT" };
  const payload = {
    iss: "did:example:authority", sub: "did:example:acme-corp",
    nbf: Math.floor(Date.now() / 1000) - 3600, exp: Math.floor(Date.now() / 1000) + 86400,
    vc: { "@context": ["https://www.w3.org/ns/credentials/v2"], type: ["VerifiableCredential"],
      credentialSubject: { id: "did:example:acme-corp", name: "Acme Corporation", largeField: "x".repeat(15_000) } },
  };
  return [Buffer.from(JSON.stringify(header)).toString("base64url"), Buffer.from(JSON.stringify(payload)).toString("base64url"), Buffer.from("fake-signature-for-testing").toString("base64url")].join(".");
}

function makeOversizedSdJwtVc() {
  const header = { alg: "ES256", typ: "sd+jwt" };
  const payload = {
    iss: "did:example:authority", sub: "did:example:acme-corp",
    nbf: Math.floor(Date.now() / 1000) - 3600, exp: Math.floor(Date.now() / 1000) + 86400,
    vct: "BusinessRegistrationCredential",
    credentialSubject: { id: "did:example:acme-corp", name: "Acme Corporation", largeField: "x".repeat(15_000) },
  };
  const issuerJwt = [Buffer.from(JSON.stringify(header)).toString("base64url"), Buffer.from(JSON.stringify(payload)).toString("base64url"), Buffer.from("fake-sig").toString("base64url")].join(".");
  return `${issuerJwt}~`;
}

function createTestApp(overrides: Partial<BusinessVcOnboardingDeps> = {}) {
  const app = new Hono();
  app.route("/onboarding", createBusinessVcOnboardingRoutes({
    jwtSigningKey: overrides.jwtSigningKey ?? TEST_JWT_KEY,
    jwtIssuer: overrides.jwtIssuer ?? TEST_JWT_ISSUER,
    jwtExpirySeconds: overrides.jwtExpirySeconds ?? TEST_JWT_EXPIRY,
    verifierConfig: overrides.verifierConfig,
    dediClient: overrides.dediClient,
    opencredSigningKeyDid: overrides.opencredSigningKeyDid ?? TEST_OPENCRED_DID,
  }));
  app.onError(errorHandler(logger));
  return app;
}

function postBusinessVc(app: Hono, body: unknown) {
  return app.request("/onboarding/business-vc", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

describe("JWT payload bounds check (#139)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedVerify.mockResolvedValue({ code: "VALID", verified: true, checks: [{ name: "signature", passed: true }] });
  });

  it("rejects oversized JWT business credential (> 10KB)", async () => {
    const app = createTestApp();
    const res = await postBusinessVc(app, {
      businessCredential: makeOversizedVcJwt(),
      publicKey: { kty: "EC", crv: "P-256", x: "test", y: "test" },
    });
    expect(res.status).toBe(413);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("PAYLOAD_TOO_LARGE");
  });

  it("rejects oversized SD-JWT VC business credential (> 10KB)", async () => {
    const app = createTestApp();
    const res = await postBusinessVc(app, {
      businessCredential: makeOversizedSdJwtVc(),
      publicKey: { kty: "EC", crv: "P-256", x: "test", y: "test" },
    });
    expect(res.status).toBe(413);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("PAYLOAD_TOO_LARGE");
  });
});
