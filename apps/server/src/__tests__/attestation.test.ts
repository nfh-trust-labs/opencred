/**
 * Attestation endpoint tests.
 *
 * Tests the challenge/verify flow and the business VC attestation path.
 * Domain verification is mocked since we can't control DNS/HTTP in tests.
 */

import { describe, it, expect, beforeAll, beforeEach, vi, afterEach } from "vitest";
import { createTestApp, generateTestKey } from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import type { Hono } from "hono";
import type { TestKeyPair } from "./helpers.js";

let app: Hono;
let testKey: TestKeyPair;

const TEST_PUBLIC_KEY_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "WbbaSStuffyldV-nSMi3GnRhMoS9BhP3KWBaGJKRvSE",
  y: "RhQGanT5LlxUyzOhELOjhqXN8CApHBJQbXJxY0OkuiE",
};

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp();
  setActiveSigner(testKey.signer);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// POST /attestation/challenge
// ---------------------------------------------------------------------------

describe("POST /attestation/challenge", () => {
  it("creates a challenge with dns-txt method", async () => {
    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toHaveProperty("challengeId");
    expect(body).toHaveProperty("token");
    expect(body).toHaveProperty("instructions");
    expect(body).toHaveProperty("expiresAt");
    expect(typeof body.challengeId).toBe("string");
    expect(typeof body.token).toBe("string");
  });

  it("creates a challenge with http method", async () => {
    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "http" }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toHaveProperty("challengeId");
    expect(body).toHaveProperty("token");
  });

  it("rejects invalid method", async () => {
    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "carrier-pigeon" }),
    });

    expect(res.status).toBe(400);
  });

  it("rejects empty domain", async () => {
    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "", method: "dns-txt" }),
    });

    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// POST /attestation/challenge/:id/verify
// ---------------------------------------------------------------------------

describe("POST /attestation/challenge/:id/verify", () => {
  const verifyBody = {
    publicKeyJwk: TEST_PUBLIC_KEY_JWK,
    issuerDid: "did:key:z6MkTestIssuer",
    keyFingerprint: "sha256:test-fingerprint",
    keyAlgorithm: "P-256",
    verificationMethodId: "did:key:z6MkTestIssuer#z6MkTestIssuer",
    organizationName: "Test University",
  };

  it("returns 404 for missing challenge", async () => {
    const res = await app.request("/attestation/challenge/nonexistent/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    expect(res.status).toBe(404);
    const body = await res.json() as Record<string, unknown>;
    const error = body.error as Record<string, unknown>;
    expect(error.code).toBe("NOT_FOUND");
  });

  it("returns 400 for invalid publicKeyJwk", async () => {
    // First create a challenge
    const challengeRes = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
    });
    const challengeBody = await challengeRes.json() as Record<string, unknown>;
    const challengeId = challengeBody.challengeId as string;

    const res = await app.request(`/attestation/challenge/${challengeId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...verifyBody, publicKeyJwk: { bad: "data" } }),
    });

    expect(res.status).toBe(400);
  });

  it("returns 400 when domain verification fails", async () => {
    // Mock verifyDomainOwnership to return failed
    const domainVerification = await import("@opencred/domain-verification");
    vi.spyOn(domainVerification, "verifyDomainOwnership").mockResolvedValue({
      verified: false,
      domain: "example.com",
      method: "dns-txt",
      error: "DNS TXT record not found",
    });

    // Create a challenge
    const challengeRes = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
    });
    const challengeBody = await challengeRes.json() as Record<string, unknown>;
    const challengeId = challengeBody.challengeId as string;

    const res = await app.request(`/attestation/challenge/${challengeId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    const error = body.error as Record<string, unknown>;
    expect(error.code).toBe("VERIFICATION_FAILED");
  });

  it("returns signed KeyAttestationCredential on successful verification", async () => {
    // Mock verifyDomainOwnership to return success
    const domainVerification = await import("@opencred/domain-verification");
    vi.spyOn(domainVerification, "verifyDomainOwnership").mockResolvedValue({
      verified: true,
      domain: "example.com",
      method: "dns-txt",
      verifiedAt: new Date().toISOString(),
    });

    // Create a challenge
    const challengeRes = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
    });
    const challengeBody = await challengeRes.json() as Record<string, unknown>;
    const challengeId = challengeBody.challengeId as string;

    const res = await app.request(`/attestation/challenge/${challengeId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toHaveProperty("credential");

    const credential = body.credential as Record<string, unknown>;
    expect(credential.type).toEqual(["VerifiableCredential", "KeyAttestationCredential"]);
    expect(credential).toHaveProperty("proof");
    expect(credential).toHaveProperty("validFrom");
    expect(credential).toHaveProperty("validUntil");

    const subject = credential.credentialSubject as Record<string, unknown>;
    expect(subject.keyFingerprint).toBe("sha256:test-fingerprint");
    expect(subject.organizationName).toBe("Test University");

    const iv = subject.identityVerification as Record<string, unknown>;
    expect(iv.method).toBe("dns-txt");
    expect(iv.verifiedDomain).toBe("example.com");
  });

  it("deletes challenge after successful verification (single-use)", async () => {
    const domainVerification = await import("@opencred/domain-verification");
    vi.spyOn(domainVerification, "verifyDomainOwnership").mockResolvedValue({
      verified: true,
      domain: "example.com",
      method: "dns-txt",
      verifiedAt: new Date().toISOString(),
    });

    const challengeRes = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
    });
    const challengeBody = await challengeRes.json() as Record<string, unknown>;
    const challengeId = challengeBody.challengeId as string;

    // First verification should succeed
    await app.request(`/attestation/challenge/${challengeId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    // Second attempt should return 404 (challenge deleted)
    const res2 = await app.request(`/attestation/challenge/${challengeId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    expect(res2.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// POST /attestation/attest-by-vc
// ---------------------------------------------------------------------------

describe("POST /attestation/attest-by-vc", () => {
  const baseBody = {
    publicKeyJwk: TEST_PUBLIC_KEY_JWK,
    issuerDid: "did:key:z6MkTestIssuer",
    keyFingerprint: "sha256:test-fingerprint",
    keyAlgorithm: "P-256",
    verificationMethodId: "did:key:z6MkTestIssuer#z6MkTestIssuer",
  };

  it("returns signed KeyAttestationCredential on valid business VC", async () => {
    const verification = await import("@opencred/verification");
    vi.spyOn(verification, "verifyBusinessVc").mockResolvedValue({
      verification: {
        code: "VALID",
        verified: true,
        checks: [],
      },
      format: "data-integrity",
      identity: {
        organizationName: "Acme Corp",
        subjectId: "did:web:acme.com",
        additionalClaims: {},
      },
    });

    const res = await app.request("/attestation/attest-by-vc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...baseBody,
        businessVc: {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          type: ["VerifiableCredential"],
          id: "urn:uuid:biz-vc-123",
          credentialSubject: { organizationName: "Acme Corp" },
        },
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toHaveProperty("credential");

    const credential = body.credential as Record<string, unknown>;
    expect(credential.type).toEqual(["VerifiableCredential", "KeyAttestationCredential"]);

    const subject = credential.credentialSubject as Record<string, unknown>;
    expect(subject.organizationName).toBe("Acme Corp");

    const iv = subject.identityVerification as Record<string, unknown>;
    expect(iv.method).toBe("business-vc");
    expect(iv.sourceCredentialId).toBe("urn:uuid:biz-vc-123");
  });

  it("returns 400 when business VC verification fails", async () => {
    const verification = await import("@opencred/verification");
    vi.spyOn(verification, "verifyBusinessVc").mockResolvedValue({
      verification: {
        code: "INVALID",
        verified: false,
        checks: [{ name: "signature", passed: false, detail: "Signature invalid" }],
      },
      format: "data-integrity",
      identity: null,
    });

    const res = await app.request("/attestation/attest-by-vc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...baseBody,
        businessVc: "eyJhbGciOiJFUzI1NiJ9.fake.signature",
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    const error = body.error as Record<string, unknown>;
    expect(error.code).toBe("BUSINESS_VC_INVALID");
  });

  it("rejects missing publicKeyJwk.kty", async () => {
    const res = await app.request("/attestation/attest-by-vc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...baseBody,
        publicKeyJwk: { bad: "data" },
        businessVc: "some-jwt",
      }),
    });

    expect(res.status).toBe(400);
  });

  it("rejects missing issuerDid", async () => {
    const res = await app.request("/attestation/attest-by-vc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        publicKeyJwk: TEST_PUBLIC_KEY_JWK,
        keyFingerprint: "sha256:test",
        keyAlgorithm: "P-256",
        verificationMethodId: "did:key:z6Mk#z6Mk",
        businessVc: "some-jwt",
      }),
    });

    expect(res.status).toBe(400);
  });
});
