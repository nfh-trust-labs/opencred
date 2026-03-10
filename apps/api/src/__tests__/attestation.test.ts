import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import { TTLStore } from "@opencred/state";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";
import {
  createAttestationRoutes,
  type AttestationChallengeRecord,
  type AttestationRouteDeps,
} from "../routes/attestation.js";

function makeDeps(overrides: Partial<AttestationRouteDeps> = {}): AttestationRouteDeps {
  return {
    challengeStore: new TTLStore<AttestationChallengeRecord>(86400000, 60000),
    dnsResolveTxt: vi.fn().mockResolvedValue([]),
    httpFetch: vi.fn().mockResolvedValue({ ok: false, text: async () => "" }),
    dnsResolve4: vi.fn().mockResolvedValue(["93.184.216.34"]),
    dnsResolve6: vi.fn().mockResolvedValue([]),
    ...overrides,
  };
}

function validChallengeBody() {
  return {
    domain: "university.example",
    method: "dns-txt" as const,
    publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
    organizationName: "Example University",
    issuerDid: "did:key:z6MkIssuer",
    verificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
    keyFingerprint: "sha256:a1b2c3d4",
    keyAlgorithm: "P-256",
  };
}

function makeApp(deps: AttestationRouteDeps) {
  const app = new Hono();
  app.route("/attestation", createAttestationRoutes(deps));
  app.onError(errorHandler(makeTestLogger()));
  return app;
}

describe("POST /attestation/challenge", () => {
  it("creates a DNS challenge with correct format", async () => {
    const deps = makeDeps();
    const app = makeApp(deps);

    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validChallengeBody()),
    });

    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.challengeId).toMatch(/^ch_/);
    expect(body.challenge).toMatch(/^opencred-verify=/);
    expect(body.instructions).toContain("DNS TXT record");
    expect(body.expiresAt).toBeDefined();
  });

  it("creates an HTTP challenge with correct format", async () => {
    const deps = makeDeps();
    const app = makeApp(deps);

    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...validChallengeBody(), method: "http-challenge" }),
    });

    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.instructions).toContain(".well-known/opencred-challenge");
  });

  it("rejects invalid domain", async () => {
    const deps = makeDeps();
    const app = makeApp(deps);

    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...validChallengeBody(), domain: "not valid" }),
    });

    expect(res.status).toBe(400);
  });

  it("rejects missing organizationName", async () => {
    const deps = makeDeps();
    const app = makeApp(deps);

    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...validChallengeBody(), organizationName: "" }),
    });

    expect(res.status).toBe(400);
  });

  it("rejects invalid issuerDid", async () => {
    const deps = makeDeps();
    const app = makeApp(deps);

    const res = await app.request("/attestation/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...validChallengeBody(), issuerDid: "not-a-did" }),
    });

    expect(res.status).toBe(400);
  });

  it("returns 405 for GET", async () => {
    const deps = makeDeps();
    const app = makeApp(deps);

    const res = await app.request("/attestation/challenge", { method: "GET" });
    expect(res.status).toBe(405);
  });
});

describe("POST /attestation/challenge/:id/verify", () => {
  it("returns 404 for non-existent challenge", async () => {
    const deps = makeDeps();
    const app = makeApp(deps);

    const res = await app.request("/attestation/challenge/ch_nonexistent/verify", {
      method: "POST",
    });
    expect(res.status).toBe(404);
  });

  it("verifies DNS challenge and returns attestation VC", async () => {
    const store = new TTLStore<AttestationChallengeRecord>(86400000, 60000);
    const token = "test-token-abc123";

    // Pre-populate a challenge
    const record: AttestationChallengeRecord = {
      id: "ch_test1",
      domain: "university.example",
      method: "dns-txt",
      token,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      verified: false,
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      organizationName: "Example University",
      issuerDid: "did:key:z6MkIssuer",
      verificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
      keyFingerprint: "sha256:a1b2c3d4",
      keyAlgorithm: "P-256",
    };
    store.set("ch_test1", record, 86400000);

    // Mock DNS resolvers all returning the correct token
    const dnsResolveTxt = vi.fn().mockResolvedValue([[`opencred-verify=${token}`]]);

    // Mock signing key provider — getActiveKey returns a SigningKey with a KeyObject
    const { generateKeyPairSync } = await import("node:crypto");
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const signingKeyProvider = {
      getActiveKey: vi.fn().mockReturnValue({
        id: "did:key:z6MkOpenCred#z6MkOpenCred",
        privateKey,
        publicKey,
        algorithm: "P-256",
      }),
    } as unknown as import("@opencred/crypto").SigningKeyProvider;

    const mockProofConfig = {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      verificationMethod: "did:key:z6MkOpenCred",
      proofPurpose: "assertionMethod",
      created: new Date().toISOString(),
      "@context": "https://w3id.org/security/data-integrity/v1",
    };
    const mockPrepareProof = vi.fn().mockResolvedValue({
      dataToSign: new Uint8Array(32),
      proofConfig: mockProofConfig,
    });
    const mockCompleteProof = vi.fn().mockImplementation((cred, _config, _sig) => ({
      ...cred,
      proof: { ...mockProofConfig, proofValue: "zmockSignature" },
    }));

    const deps = makeDeps({
      challengeStore: store,
      dnsResolveTxt,
      signingKeyProvider,
      opencredDid: "did:key:z6MkOpenCred",
      prepareProof: mockPrepareProof as never,
      completeProof: mockCompleteProof as never,
    });

    const app = makeApp(deps);
    const res = await app.request("/attestation/challenge/ch_test1/verify", { method: "POST" });

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.verified).toBe(true);
    expect(body.attestationCredential).toBeDefined();

    const vc = body.attestationCredential as Record<string, unknown>;
    expect(vc.type).toContain("KeyAttestationCredential");
    expect(vc.issuer).toBe("did:key:z6MkOpenCred");
  });

  it("returns cached attestation on re-verify", async () => {
    const store = new TTLStore<AttestationChallengeRecord>(86400000, 60000);
    const cachedVC = { type: ["VerifiableCredential", "KeyAttestationCredential"], cached: true };

    const record: AttestationChallengeRecord = {
      id: "ch_cached",
      domain: "university.example",
      method: "dns-txt",
      token: "cached-token",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      verified: true,
      verifiedAt: new Date().toISOString(),
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      organizationName: "Example University",
      issuerDid: "did:key:z6MkIssuer",
      verificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
      keyFingerprint: "sha256:a1b2c3d4",
      keyAlgorithm: "P-256",
      attestationCredential: cachedVC,
    };
    store.set("ch_cached", record, 86400000);

    const deps = makeDeps({ challengeStore: store });
    const app = makeApp(deps);
    const res = await app.request("/attestation/challenge/ch_cached/verify", { method: "POST" });

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.verified).toBe(true);
    const vc = body.attestationCredential as Record<string, boolean>;
    expect(vc.cached).toBe(true);
  });

  it("returns 422 when DNS verification fails", async () => {
    const store = new TTLStore<AttestationChallengeRecord>(86400000, 60000);

    const record: AttestationChallengeRecord = {
      id: "ch_fail",
      domain: "university.example",
      method: "dns-txt",
      token: "fail-token",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      verified: false,
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      organizationName: "Example University",
      issuerDid: "did:key:z6MkIssuer",
      verificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
      keyFingerprint: "sha256:a1b2c3d4",
      keyAlgorithm: "P-256",
    };
    store.set("ch_fail", record, 86400000);

    // All resolvers return empty (no matching record)
    const dnsResolveTxt = vi.fn().mockResolvedValue([["something-else"]]);

    const deps = makeDeps({ challengeStore: store, dnsResolveTxt });
    const app = makeApp(deps);
    const res = await app.request("/attestation/challenge/ch_fail/verify", { method: "POST" });

    expect(res.status).toBe(400);
  });

  it("returns 501 when signing key not configured", async () => {
    const store = new TTLStore<AttestationChallengeRecord>(86400000, 60000);
    const token = "no-signer-token";

    const record: AttestationChallengeRecord = {
      id: "ch_nosigner",
      domain: "university.example",
      method: "dns-txt",
      token,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      verified: false,
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      organizationName: "Example University",
      issuerDid: "did:key:z6MkIssuer",
      verificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
      keyFingerprint: "sha256:a1b2c3d4",
      keyAlgorithm: "P-256",
    };
    store.set("ch_nosigner", record, 86400000);

    const dnsResolveTxt = vi.fn().mockResolvedValue([[`opencred-verify=${token}`]]);

    const deps = makeDeps({
      challengeStore: store,
      dnsResolveTxt,
      signingKeyProvider: undefined,
      opencredDid: undefined,
    });

    const app = makeApp(deps);
    const res = await app.request("/attestation/challenge/ch_nosigner/verify", { method: "POST" });

    expect(res.status).toBe(501);
  });

  it("rejects HTTP challenge to private IP", async () => {
    const store = new TTLStore<AttestationChallengeRecord>(86400000, 60000);

    const record: AttestationChallengeRecord = {
      id: "ch_ssrf",
      domain: "evil.example",
      method: "http-challenge",
      token: "ssrf-token",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      verified: false,
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      organizationName: "Evil Corp",
      issuerDid: "did:key:z6MkEvil",
      verificationMethodId: "did:key:z6MkEvil#z6MkEvil",
      keyFingerprint: "sha256:evil",
      keyAlgorithm: "P-256",
    };
    store.set("ch_ssrf", record, 86400000);

    const deps = makeDeps({
      challengeStore: store,
      dnsResolve4: vi.fn().mockResolvedValue(["192.168.1.1"]),
    });

    const app = makeApp(deps);
    const res = await app.request("/attestation/challenge/ch_ssrf/verify", { method: "POST" });

    expect(res.status).toBe(400);
  });
});
