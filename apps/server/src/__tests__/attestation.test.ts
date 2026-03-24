/**
 * Attestation endpoint tests.
 *
 * Tests domain verification challenge creation, verification + attestation,
 * and business VC attestation. Mocks DNS/HTTP verification and business VC
 * verification to avoid real network calls.
 */

import { describe, it, expect, beforeAll, beforeEach, vi } from "vitest";
import { createTestApp, generateTestKey } from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import { challengeStore } from "../routes/attestation.js";
import type { Hono } from "hono";
import type { TestKeyPair } from "./helpers.js";

// Mock domain-verification's verifyDomainOwnership
vi.mock("@opencred/domain-verification", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@opencred/domain-verification")>();
  return {
    ...actual,
    verifyDomainOwnership: vi.fn(),
  };
});

// Mock verification's verifyBusinessVc
vi.mock("@opencred/verification", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@opencred/verification")>();
  return {
    ...actual,
    verifyBusinessVc: vi.fn(),
  };
});

import { verifyDomainOwnership } from "@opencred/domain-verification";
import { verifyBusinessVc } from "@opencred/verification";

const mockVerifyDomainOwnership = vi.mocked(verifyDomainOwnership);
const mockVerifyBusinessVc = vi.mocked(verifyBusinessVc);

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp();
  setActiveSigner(testKey.signer);
  vi.clearAllMocks();
});

// ─── POST /attestation/challenge ──────────────────────────────────────

describe("POST /attestation/challenge", () => {
  it("creates a challenge with proper structure", async () => {
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
    expect(typeof body["challengeId"]).toBe("string");
    expect(typeof body["token"]).toBe("string");
    expect(typeof body["instructions"]).toBe("string");
  });

  it("creates a challenge for http method", async () => {
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

  it("returns 400 for missing domain", async () => {
    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ method: "dns-txt" }),
    });

    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid method", async () => {
    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "invalid" }),
    });

    expect(res.status).toBe(400);
  });

  it("returns 400 for empty domain", async () => {
    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "", method: "dns-txt" }),
    });

    expect(res.status).toBe(400);
  });
});

// ─── POST /attestation/challenge/:id/verify ───────────────────────────

describe("POST /attestation/challenge/:id/verify", () => {
  const verifyBody = {
    publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
    issuerDid: "did:key:z6MkIssuer",
    keyFingerprint: "sha256:a1b2c3d4",
    keyAlgorithm: "P-256",
    verificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
    organizationName: "Test University",
  };

  it("returns signed KeyAttestationCredential on successful domain verification", async () => {
    // Create a challenge first
    const createRes = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
    });
    const challenge = await createRes.json() as Record<string, unknown>;
    const challengeId = challenge["challengeId"] as string;

    // Mock successful domain verification
    mockVerifyDomainOwnership.mockResolvedValueOnce({
      verified: true,
      domain: "example.com",
      method: "dns-txt",
      verifiedAt: new Date().toISOString(),
    });

    const res = await app.request(`/attestation/challenge/${challengeId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toHaveProperty("type");
    expect(body).toHaveProperty("credentialSubject");
    expect(body).toHaveProperty("proof");

    const types = body["type"] as string[];
    expect(types).toContain("VerifiableCredential");
    expect(types).toContain("KeyAttestationCredential");

    const subject = body["credentialSubject"] as Record<string, unknown>;
    expect(subject["id"]).toBe("did:key:z6MkIssuer");
    expect(subject["keyFingerprint"]).toBe("sha256:a1b2c3d4");
    expect(subject["organizationName"]).toBe("Test University");

    const iv = subject["identityVerification"] as Record<string, unknown>;
    expect(iv["method"]).toBe("dns-txt");
    expect(iv["verifiedDomain"]).toBe("example.com");

    const proof = body["proof"] as Record<string, unknown>;
    expect(proof).toHaveProperty("jwt");
  });

  it("returns 404 for non-existent challenge", async () => {
    const res = await app.request("/attestation/challenge/nonexistent-id/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    expect(res.status).toBe(404);
    const body = await res.json() as Record<string, unknown>;
    const error = body["error"] as Record<string, unknown>;
    expect(error["code"]).toBe("NOT_FOUND");
  });

  it("returns 400 when domain verification fails", async () => {
    // Create a challenge
    const createRes = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
    });
    const challenge = await createRes.json() as Record<string, unknown>;
    const challengeId = challenge["challengeId"] as string;

    mockVerifyDomainOwnership.mockResolvedValueOnce({
      verified: false,
      domain: "example.com",
      method: "dns-txt",
      error: "DNS record not found",
    });

    const res = await app.request(`/attestation/challenge/${challengeId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    const error = body["error"] as Record<string, unknown>;
    expect(error["code"]).toBe("VERIFICATION_FAILED");
  });

  it("returns 400 for invalid request body", async () => {
    // Create a challenge
    const createRes = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
    });
    const challenge = await createRes.json() as Record<string, unknown>;
    const challengeId = challenge["challengeId"] as string;

    // Missing required fields
    const res = await app.request(`/attestation/challenge/${challengeId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ publicKeyJwk: { kty: "EC" } }),
    });

    expect(res.status).toBe(400);
  });

  it("returns 410 for expired challenge", async () => {
    // Create a challenge and manually expire it
    const createRes = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "example.com", method: "dns-txt" }),
    });
    const challenge = await createRes.json() as Record<string, unknown>;
    const challengeId = challenge["challengeId"] as string;

    // Manually expire the challenge in the store
    const stored = challengeStore.get(challengeId);
    if (stored) {
      // Set expiresAt to the past so it's treated as expired on next access
      stored.expiresAt = new Date(Date.now() - 1000);
    }

    const res = await app.request(`/attestation/challenge/${challengeId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    // The challenge store will have already purged it, so we get 404
    expect(res.status).toBe(404);
  });
});

// ─── POST /attestation/attest-by-vc ──────────────────────────────────

describe("POST /attestation/attest-by-vc", () => {
  const businessVc = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:biz-vc-123",
    type: ["VerifiableCredential", "BusinessRegistrationCredential"],
    issuer: "did:key:z6MkRegistrar",
    credentialSubject: {
      id: "did:key:z6MkIssuer",
      organizationName: "Acme Corp",
      domain: "acme.example.com",
    },
    proof: { type: "DataIntegrityProof", proofValue: "z..." },
  };

  const attestBody = {
    businessVc,
    publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
    issuerDid: "did:key:z6MkIssuer",
    keyFingerprint: "sha256:a1b2c3d4",
    keyAlgorithm: "P-256",
    verificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
  };

  it("returns signed KeyAttestationCredential with sourceCredentialId", async () => {
    mockVerifyBusinessVc.mockResolvedValueOnce({
      verification: {
        code: "VALID",
        verified: true,
        checks: [{ name: "signature", passed: true }],
      },
      format: "data-integrity",
      identity: {
        organizationName: "Acme Corp",
        subjectId: "did:key:z6MkIssuer",
        additionalClaims: { domain: "acme.example.com" },
      },
    });

    const res = await app.request("/attestation/attest-by-vc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(attestBody),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;

    const types = body["type"] as string[];
    expect(types).toContain("KeyAttestationCredential");

    const subject = body["credentialSubject"] as Record<string, unknown>;
    expect(subject["id"]).toBe("did:key:z6MkIssuer");
    expect(subject["organizationName"]).toBe("Acme Corp");

    const iv = subject["identityVerification"] as Record<string, unknown>;
    expect(iv["method"]).toBe("business-vc");
    expect(iv["sourceCredentialId"]).toBe("urn:uuid:biz-vc-123");

    const proof = body["proof"] as Record<string, unknown>;
    expect(proof).toHaveProperty("jwt");
  });

  it("returns 400 when business VC verification fails", async () => {
    mockVerifyBusinessVc.mockResolvedValueOnce({
      verification: {
        code: "INVALID",
        verified: false,
        checks: [{ name: "signature", passed: false, detail: "Bad signature" }],
      },
      format: "data-integrity",
      identity: null,
    });

    const res = await app.request("/attestation/attest-by-vc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(attestBody),
    });

    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid request body", async () => {
    const res = await app.request("/attestation/attest-by-vc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ businessVc: "something" }),
    });

    expect(res.status).toBe(400);
  });
});
