import { describe, it, expect } from "vitest";
import { createSign, generateKeyPairSync } from "node:crypto";
import { Hono } from "hono";
import { createCapabilityToken } from "@opencred/auth";
import { createCredentialsRoute } from "../routes/credentials.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestConfig, makeTestLogger } from "./helpers.js";

// -------------------------------------------------------------------------
// Test infrastructure
// -------------------------------------------------------------------------

const TEST_SECRET = new TextEncoder().encode("test-secret-key-that-is-at-least-32-bytes-long!!");
const logger = makeTestLogger();

// Generate a real P-256 key pair for the "issuer"
const { publicKey: issuerPublicKey, privateKey: issuerPrivateKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});

const issuerPubJwk = issuerPublicKey.export({ format: "jwk" });
const issuerPublicKeyId = `z${issuerPubJwk.x!.slice(0, 10)}`;

const AUTH_OPTIONS = {
  verificationKey: TEST_SECRET,
  issuer: "opencred",
  algorithms: ["HS256"] as string[],
};

async function makeToken(scope: string[] = ["credentials:build"]) {
  return createCapabilityToken({
    subject: "issuer-1",
    issuer: "opencred",
    expiresInSeconds: 3600,
    scope,
    namespace: "default",
    signingKey: TEST_SECRET,
    algorithm: "HS256",
  });
}

function createTestApp() {
  const config = makeTestConfig();
  const { credentials, sessionStore } = createCredentialsRoute({
    config,
    authOptions: AUTH_OPTIONS,
  });
  const app = new Hono();
  app.route("/credentials", credentials);
  app.onError(errorHandler(logger));
  return { app, sessionStore };
}

const VALID_BUILD_BODY = {
  schema: "education",
  issuer: "did:web:university.example",
  publicKey: issuerPublicKeyId,
  credentialSubject: {
    name: "Jane Doe",
    degree: "Bachelor of Science",
    institution: "Example University",
    dateConferred: "2025-06-15",
  },
  validFrom: "2026-01-01T00:00:00Z",
  validUntil: "2027-01-01T00:00:00Z",
  revocationRegistryUrl: "https://dedi.example/revocations/university.example/reg",
};

interface ErrorBody {
  error: { code: string; message: string; validationErrors?: unknown[] };
}

interface BuildResponse {
  sessionId: string;
  unsignedCredential: Record<string, unknown>;
  dataToSign: string;
  proofConfig: Record<string, unknown>;
}

interface PackageResponse {
  credential: Record<string, unknown> & { proof: Record<string, unknown> };
  formats: { jsonld: Record<string, unknown> };
}

// -------------------------------------------------------------------------
// Helper: sign dataToSign with the issuer's private key
// -------------------------------------------------------------------------
function signData(dataToSignBase64url: string): string {
  const padded = dataToSignBase64url.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  const signer = createSign("SHA256");
  signer.update(bytes);
  const sig = signer.sign({ key: issuerPrivateKey, dsaEncoding: "ieee-p1363" });

  const sigBinary = String.fromCharCode(...new Uint8Array(sig));
  return btoa(sigBinary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// -------------------------------------------------------------------------
// Tests: POST /credentials/build
// -------------------------------------------------------------------------

describe("POST /credentials/build", () => {
  it("returns 401 without auth token", async () => {
    const { app } = createTestApp();
    const res = await app.request("/credentials/build", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(VALID_BUILD_BODY),
    });
    expect(res.status).toBe(401);
  });

  it("returns 403 with wrong scope", async () => {
    const { app } = createTestApp();
    const token = await makeToken(["credentials:read"]);
    const res = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BUILD_BODY),
    });
    expect(res.status).toBe(403);
  });

  it("returns 400 for missing required fields", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });

  it("returns 404 for unknown schema", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...VALID_BUILD_BODY,
        schema: "nonexistent-schema",
      }),
    });
    expect(res.status).toBe(404);
  });

  it("returns 400 for invalid credentialSubject that fails schema validation", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...VALID_BUILD_BODY,
        credentialSubject: { name: "Jane Doe" },
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("SCHEMA_VALIDATION_ERROR");
  });

  it("returns 400 for non-HTTPS revocationRegistryUrl", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...VALID_BUILD_BODY,
        revocationRegistryUrl: "http://insecure.example/rev",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("HTTPS");
  });

  it("returns 400 for unparseable revocationRegistryUrl", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...VALID_BUILD_BODY,
        revocationRegistryUrl: "not-a-url",
      }),
    });
    expect(res.status).toBe(400);
  });

  it("returns 201 with sessionId, unsignedCredential, dataToSign, and proofConfig", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BUILD_BODY),
    });
    const body = await res.json();
    expect(res.status, `Expected 201 but got ${res.status}: ${JSON.stringify(body)}`).toBe(201);

    const buildBody = body as BuildResponse;
    expect(buildBody.sessionId).toBeDefined();
    expect(buildBody.unsignedCredential).toBeDefined();
    expect(buildBody.dataToSign).toBeDefined();
    expect(buildBody.proofConfig).toBeDefined();

    const vc = buildBody.unsignedCredential;
    expect(vc["@context"]).toContain("https://www.w3.org/ns/credentials/v2");
    expect(vc.type).toContain("VerifiableCredential");
    expect(vc.issuer).toBe("did:web:university.example");
    expect(vc.validFrom).toBe("2026-01-01T00:00:00Z");
    expect(vc.validUntil).toBe("2027-01-01T00:00:00Z");

    expect(buildBody.proofConfig.type).toBe("DataIntegrityProof");
    expect(buildBody.proofConfig.cryptosuite).toBe("ecdsa-rdfc-2019");
    expect(buildBody.proofConfig.proofPurpose).toBe("assertionMethod");
  });
});

// -------------------------------------------------------------------------
// Tests: POST /credentials/package
// -------------------------------------------------------------------------

describe("POST /credentials/package", () => {
  it("returns 410 for non-existent session", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/package", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        sessionId: "00000000-0000-0000-0000-000000000000",
        signature: "AAAA",
      }),
    });
    expect(res.status).toBe(410);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("SESSION_EXPIRED");
  });

  it("returns 400 for invalid signature length", async () => {
    const { app } = createTestApp();
    const token = await makeToken();

    // Build to create a session
    const buildRes = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BUILD_BODY),
    });
    const buildBody = await buildRes.json();
    expect(buildRes.status, `Build failed: ${JSON.stringify(buildBody)}`).toBe(201);

    // Package with a too-short signature
    const shortSig = btoa("short").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const res = await app.request("/credentials/package", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        sessionId: (buildBody as BuildResponse).sessionId,
        signature: shortSig,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("64 bytes");
  });

  it("returns 400 for missing fields", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/package", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
  });

  it("returns 401 without auth", async () => {
    const { app } = createTestApp();
    const res = await app.request("/credentials/package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: "00000000-0000-0000-0000-000000000000",
        signature: "AAAA",
      }),
    });
    expect(res.status).toBe(401);
  });
});

// -------------------------------------------------------------------------
// Tests: Full round-trip
// -------------------------------------------------------------------------

describe("Full round-trip: build -> sign -> package", () => {
  it("produces a valid VerifiableCredential with proof", async () => {
    const { app } = createTestApp();
    const token = await makeToken();

    // Step 1: Build
    const buildRes = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BUILD_BODY),
    });
    const buildBody = await buildRes.json();
    expect(buildRes.status, `Build failed: ${JSON.stringify(buildBody)}`).toBe(201);

    const build = buildBody as BuildResponse;

    // Step 2: Sign the dataToSign externally
    const signature = signData(build.dataToSign);

    // Step 3: Package
    const packageRes = await app.request("/credentials/package", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        sessionId: build.sessionId,
        signature,
      }),
    });
    expect(packageRes.status).toBe(200);
    const packageBody = (await packageRes.json()) as PackageResponse;

    const vc = packageBody.credential;
    expect(vc["@context"]).toContain("https://www.w3.org/ns/credentials/v2");
    expect(vc.type).toContain("VerifiableCredential");
    expect(vc.issuer).toBe("did:web:university.example");
    expect(vc.proof).toBeDefined();
    expect(vc.proof.type).toBe("DataIntegrityProof");
    expect(vc.proof.cryptosuite).toBe("ecdsa-rdfc-2019");
    expect(vc.proof.proofPurpose).toBe("assertionMethod");
    expect(vc.proof.proofValue).toBeDefined();
    expect(typeof vc.proof.proofValue).toBe("string");

    expect(packageBody.formats.jsonld).toBeDefined();
    expect(packageBody.formats.jsonld).toEqual(vc);
  });

  it("consumes the session after packaging (one-time use)", async () => {
    const { app } = createTestApp();
    const token = await makeToken();

    // Build
    const buildRes = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BUILD_BODY),
    });
    const buildBody = (await buildRes.json()) as BuildResponse;
    expect(buildRes.status).toBe(201);

    // Sign and package
    const signature = signData(buildBody.dataToSign);
    const packageRes = await app.request("/credentials/package", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        sessionId: buildBody.sessionId,
        signature,
      }),
    });
    expect(packageRes.status).toBe(200);

    // Try to package again — should fail with expired session
    const secondRes = await app.request("/credentials/package", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        sessionId: buildBody.sessionId,
        signature,
      }),
    });
    expect(secondRes.status).toBe(410);
  });
});

// -------------------------------------------------------------------------
// Tests: Session expiry
// -------------------------------------------------------------------------

describe("Session expiry", () => {
  it("rejects packaging after session TTL expires", async () => {
    const config = makeTestConfig({ SESSION_TTL_MS: 1, SESSION_SWEEP_INTERVAL_MS: 100000 });
    const { credentials, sessionStore } = createCredentialsRoute({
      config,
      authOptions: AUTH_OPTIONS,
    });
    const app = new Hono();
    app.route("/credentials", credentials);
    app.onError(errorHandler(logger));

    const token = await makeToken();

    // Build
    const buildRes = await app.request("/credentials/build", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BUILD_BODY),
    });
    const buildBody = await buildRes.json();
    expect(buildRes.status, `Build failed: ${JSON.stringify(buildBody)}`).toBe(201);

    // Wait for TTL to expire
    await new Promise((r) => setTimeout(r, 10));

    const signature = signData((buildBody as BuildResponse).dataToSign);
    const packageRes = await app.request("/credentials/package", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        sessionId: (buildBody as BuildResponse).sessionId,
        signature,
      }),
    });
    expect(packageRes.status).toBe(410);

    sessionStore.destroy();
  });
});
