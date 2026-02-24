import { describe, it, expect, vi } from "vitest";
import { createSign, generateKeyPairSync } from "node:crypto";
import { Hono } from "hono";
import { createCapabilityToken } from "@opencred/auth";
import { LocalSigningKeyProvider } from "@opencred/crypto";
import type { DeDiClient } from "@opencred/dedi-client";
import type { DelegationCertificate } from "@opencred/delegation";
import { createBatchRoute, createBatchRevokeRoute } from "../routes/batch.js";
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

const signingKeyProvider = new LocalSigningKeyProvider();
const activeKey = signingKeyProvider.getActiveKey();

const AUTH_OPTIONS = {
  verificationKey: TEST_SECRET,
  issuer: "opencred",
  algorithms: ["HS256"] as string[],
};

async function makeToken(scope: string[] = ["credentials:batch"]) {
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

// -------------------------------------------------------------------------
// Mock DeDi client
// -------------------------------------------------------------------------

function makeActiveDelegation(): DelegationCertificate {
  const now = new Date();
  const validFrom = new Date(now.getTime() - 86400000).toISOString();
  const validUntil = new Date(now.getTime() + 86400000).toISOString();

  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://opencred.example/ns/delegation/v1",
    ],
    id: "urn:uuid:delegation-1",
    type: ["DelegationCertificate"],
    delegator: {
      id: "https://university.example",
      name: "Example University",
    },
    delegatee: {
      id: activeKey.id,
    },
    scope: {
      credentialTypes: ["education"],
      namespaces: ["education"],
    },
    validFrom,
    validUntil,
    authorisationPath: "dedi-registry",
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: validFrom,
      verificationMethod: "https://university.example#key-1",
      proofPurpose: "assertionMethod",
      proofValue: "zMockProofValue",
    },
  };
}

function createMockDediClient(
  delegation: DelegationCertificate | null = makeActiveDelegation(),
  options: { revoked?: boolean; publishFails?: boolean } = {},
): DeDiClient {
  const { revoked = false, publishFails = false } = options;
  return {
    resolveDelegation: vi.fn().mockImplementation(async (id: string) => {
      if (!delegation) {
        throw new Error(`Delegation ${id} not found`);
      }
      return { id, certificate: delegation };
    }),
    registerDelegation: vi.fn().mockResolvedValue({}),
    queryRevocationHash: vi.fn().mockResolvedValue({ revoked, hash: "mock-hash" }),
    publishRevocationHash: vi.fn().mockImplementation(async (hash: string) => {
      if (publishFails) {
        throw new Error("DeDi publish failed");
      }
      return { hash, revoked: true, revokedAt: new Date().toISOString() };
    }),
    resolveDID: vi.fn().mockResolvedValue({ did: "did:web:example" }),
  } as unknown as DeDiClient;
}

// -------------------------------------------------------------------------
// App factories
// -------------------------------------------------------------------------

function createBatchApp(options?: {
  delegation?: DelegationCertificate | null;
  revoked?: boolean;
  maxBatchSize?: number;
}) {
  const config = makeTestConfig({
    DEDI_API_URL: "https://dedi.opencred.test",
    MAX_BATCH_SIZE: options?.maxBatchSize ?? 1000,
  });
  const dediClient = createMockDediClient(options?.delegation, { revoked: options?.revoked });
  const { batch, jobStore } = createBatchRoute({
    config,
    authOptions: AUTH_OPTIONS,
    signingKeyProvider,
    dediClient,
  });
  const app = new Hono();
  app.route("/credentials/batch", batch);
  app.onError(errorHandler(logger));
  return { app, jobStore, dediClient };
}

function createBatchRevokeApp(options?: { publishFails?: boolean }) {
  const dediClient = createMockDediClient(null, { publishFails: options?.publishFails });
  const revokeRoute = createBatchRevokeRoute(dediClient);
  const app = new Hono();
  app.route("/", revokeRoute);
  app.onError(errorHandler(logger));
  return { app, dediClient };
}

// -------------------------------------------------------------------------
// Test data
// -------------------------------------------------------------------------

const VALID_INTERFACE_BATCH = {
  schema: "education",
  signingFlow: "interface" as const,
  issuer: "did:web:university.example",
  publicKey: issuerPublicKeyId,
  revocationRegistryUrl: "https://dedi.example/revocations/university.example/reg",
  credentials: [
    {
      credentialSubject: {
        name: "Jane Doe",
        degree: "Bachelor of Science",
        institution: "Example University",
        dateConferred: "2025-06-15",
      },
      validFrom: "2026-01-01T00:00:00Z",
    },
    {
      credentialSubject: {
        name: "John Smith",
        degree: "Master of Arts",
        institution: "Example University",
        dateConferred: "2025-06-15",
      },
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2027-01-01T00:00:00Z",
    },
  ],
};

const VALID_DELEGATED_BATCH = {
  schema: "education",
  signingFlow: "delegated" as const,
  delegationId: "urn:uuid:delegation-1",
  credentials: [
    {
      credentialSubject: {
        name: "Jane Doe",
        degree: "Bachelor of Science",
        institution: "Example University",
        dateConferred: "2025-06-15",
      },
      validFrom: "2026-01-01T00:00:00Z",
    },
    {
      credentialSubject: {
        name: "John Smith",
        degree: "Master of Arts",
        institution: "Example University",
        dateConferred: "2025-06-15",
      },
      validFrom: "2026-01-01T00:00:00Z",
    },
  ],
};

interface ErrorBody {
  error: { code: string; message: string; validationErrors?: unknown[] };
}

interface BatchSubmitResponse {
  jobId: string;
  status: string;
  total: number;
  succeeded: number;
  failed: number;
  message?: string;
}

interface BatchResultsResponse {
  jobId: string;
  status: string;
  total: number;
  succeeded: number;
  failed: number;
  results: Array<{
    index: number;
    status: string;
    credential?: Record<string, unknown>;
    error?: string;
    dataToSign?: string;
    unsignedCredential?: Record<string, unknown>;
    proofConfig?: Record<string, unknown>;
  }>;
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

// =========================================================================
// Tests: POST /credentials/batch — Submit batch
// =========================================================================

describe("POST /credentials/batch", () => {
  it("returns 401 without auth token", async () => {
    const { app } = createBatchApp();
    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(VALID_INTERFACE_BATCH),
    });
    expect(res.status).toBe(401);
  });

  it("returns 403 with wrong scope", async () => {
    const { app } = createBatchApp();
    const token = await makeToken(["credentials:read"]);
    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_INTERFACE_BATCH),
    });
    expect(res.status).toBe(403);
  });

  it("returns 400 for missing required fields", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();
    const res = await app.request("/credentials/batch", {
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

  it("returns 400 for empty credentials array", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();
    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...VALID_INTERFACE_BATCH,
        credentials: [],
      }),
    });
    expect(res.status).toBe(400);
  });

  it("returns 400 when batch exceeds MAX_BATCH_SIZE", async () => {
    const { app } = createBatchApp({ maxBatchSize: 2 });
    const token = await makeToken();
    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...VALID_INTERFACE_BATCH,
        credentials: [...VALID_INTERFACE_BATCH.credentials, ...VALID_INTERFACE_BATCH.credentials],
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("exceeds maximum");
  });

  it("returns 400 for interface signing without issuer", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();
    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...VALID_INTERFACE_BATCH,
        issuer: undefined,
      }),
    });
    expect(res.status).toBe(400);
  });

  it("returns 400 for delegated signing without delegationId", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();
    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        schema: "education",
        signingFlow: "delegated",
        credentials: VALID_DELEGATED_BATCH.credentials,
      }),
    });
    expect(res.status).toBe(400);
  });

  it("returns 404 for unknown schema", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();
    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...VALID_INTERFACE_BATCH,
        schema: "nonexistent-schema",
      }),
    });
    expect(res.status).toBe(404);
  });
});

// =========================================================================
// Tests: Batch validation — two-phase (validate-first)
// =========================================================================

describe("Batch validation (validate-first, then issue)", () => {
  it("rejects entire batch when some rows fail schema validation", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const batchWithInvalidRows = {
      ...VALID_INTERFACE_BATCH,
      credentials: [
        VALID_INTERFACE_BATCH.credentials[0],
        {
          credentialSubject: { name: "Missing fields" },
          validFrom: "2026-01-01T00:00:00Z",
        },
      ],
    };

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(batchWithInvalidRows),
    });

    expect(res.status).toBe(202);
    const body = (await res.json()) as BatchSubmitResponse;
    expect(body.status).toBe("failed");
    expect(body.failed).toBeGreaterThan(0);
    expect(body.message).toContain("validation failed");
  });

  it("reports per-row validation errors in results", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const batchWithInvalidRows = {
      ...VALID_INTERFACE_BATCH,
      credentials: [
        {
          credentialSubject: { name: "Only name" },
          validFrom: "2026-01-01T00:00:00Z",
        },
        VALID_INTERFACE_BATCH.credentials[1],
      ],
    };

    // Submit batch
    const submitRes = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(batchWithInvalidRows),
    });

    const submitBody = (await submitRes.json()) as BatchSubmitResponse;
    expect(submitBody.status).toBe("failed");

    // Get results
    const resultsRes = await app.request(`/credentials/batch/${submitBody.jobId}/results`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(resultsRes.status).toBe(200);
    const resultsBody = (await resultsRes.json()) as BatchResultsResponse;
    expect(resultsBody.results[0].status).toBe("failed");
    expect(resultsBody.results[0].error).toContain("Validation failed");
    // Row 1 was valid but batch was rejected, so it stays pending
    expect(resultsBody.results[1].status).toBe("pending");
  });
});

// =========================================================================
// Tests: Interface Signing batch round-trip
// =========================================================================

describe("Interface Signing batch round-trip", () => {
  it("returns awaiting_signatures status with signing data for all rows", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_INTERFACE_BATCH),
    });

    expect(res.status).toBe(202);
    const body = (await res.json()) as BatchSubmitResponse;
    expect(body.status).toBe("awaiting_signatures");
    expect(body.total).toBe(2);
    expect(body.succeeded).toBe(0);
    expect(body.failed).toBe(0);

    // Get results to check signing data
    const resultsRes = await app.request(`/credentials/batch/${body.jobId}/results`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    const resultsBody = (await resultsRes.json()) as BatchResultsResponse;
    expect(resultsBody.results).toHaveLength(2);
    for (const row of resultsBody.results) {
      expect(row.status).toBe("awaiting_signature");
      expect(row.dataToSign).toBeDefined();
      expect(row.unsignedCredential).toBeDefined();
      expect(row.proofConfig).toBeDefined();
    }
  });

  it("completes full round-trip: submit -> get signing data -> submit signatures -> get results", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    // Step 1: Submit batch
    const submitRes = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_INTERFACE_BATCH),
    });

    const submitBody = (await submitRes.json()) as BatchSubmitResponse;
    expect(submitBody.status).toBe("awaiting_signatures");
    const jobId = submitBody.jobId;

    // Step 2: Get signing data
    const resultsRes = await app.request(`/credentials/batch/${jobId}/results`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    const resultsBody = (await resultsRes.json()) as BatchResultsResponse;

    // Step 3: Sign each credential
    const signatures = resultsBody.results.map((row) => ({
      index: row.index,
      signature: signData(row.dataToSign!),
    }));

    // Step 4: Submit signatures
    const sigRes = await app.request(`/credentials/batch/${jobId}/signatures`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ signatures }),
    });

    expect(sigRes.status).toBe(200);
    const sigBody = (await sigRes.json()) as BatchSubmitResponse;
    expect(sigBody.status).toBe("completed");
    expect(sigBody.succeeded).toBe(2);
    expect(sigBody.failed).toBe(0);

    // Step 5: Get final results with credentials
    const finalRes = await app.request(`/credentials/batch/${jobId}/results`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    const finalBody = (await finalRes.json()) as BatchResultsResponse;
    expect(finalBody.status).toBe("completed");
    for (const row of finalBody.results) {
      expect(row.status).toBe("issued");
      expect(row.credential).toBeDefined();
      const vc = row.credential!;
      expect(vc["@context"]).toContain("https://www.w3.org/ns/credentials/v2");
      expect(vc.type).toContain("VerifiableCredential");
      expect((vc.proof as Record<string, unknown>)?.type).toBe("DataIntegrityProof");
    }
  });
});

// =========================================================================
// Tests: Delegated Signing batch round-trip
// =========================================================================

describe("Delegated Signing batch round-trip", () => {
  it("completes batch issuance in a single step", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_DELEGATED_BATCH),
    });

    expect(res.status).toBe(202);
    const body = (await res.json()) as BatchSubmitResponse;
    expect(body.status).toBe("completed");
    expect(body.total).toBe(2);
    expect(body.succeeded).toBe(2);
    expect(body.failed).toBe(0);

    // Get results
    const resultsRes = await app.request(`/credentials/batch/${body.jobId}/results`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    const resultsBody = (await resultsRes.json()) as BatchResultsResponse;
    for (const row of resultsBody.results) {
      expect(row.status).toBe("issued");
      expect(row.credential).toBeDefined();
      const vc = row.credential!;
      expect(vc["@context"]).toContain("https://www.w3.org/ns/credentials/v2");
      const issuer = vc.issuer as { id: string; name?: string };
      expect(issuer.id).toBe("https://university.example");
      expect(issuer.name).toBe("Example University");
    }
  });

  it("returns 403 when delegation is expired", async () => {
    const now = new Date();
    const pastFrom = new Date(now.getTime() - 172800000).toISOString();
    const pastUntil = new Date(now.getTime() - 86400000).toISOString();
    const expired = makeActiveDelegation();
    expired.validFrom = pastFrom;
    expired.validUntil = pastUntil;

    const { app } = createBatchApp({ delegation: expired });
    const token = await makeToken();

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_DELEGATED_BATCH),
    });
    expect(res.status).toBe(403);
  });

  it("returns 403 when delegation is revoked", async () => {
    const { app } = createBatchApp({ revoked: true });
    const token = await makeToken();

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_DELEGATED_BATCH),
    });
    expect(res.status).toBe(403);
  });
});

// =========================================================================
// Tests: GET /credentials/batch/:jobId — Poll status
// =========================================================================

describe("GET /credentials/batch/:jobId", () => {
  it("returns current job status", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    // Submit a batch
    const submitRes = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_INTERFACE_BATCH),
    });
    const submitBody = (await submitRes.json()) as BatchSubmitResponse;

    // Poll
    const pollRes = await app.request(`/credentials/batch/${submitBody.jobId}`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(pollRes.status).toBe(200);
    const pollBody = (await pollRes.json()) as BatchSubmitResponse;
    expect(pollBody.jobId).toBe(submitBody.jobId);
    expect(pollBody.status).toBe("awaiting_signatures");
    expect(pollBody.total).toBe(2);
  });

  it("returns 410 for non-existent job", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const res = await app.request("/credentials/batch/00000000-0000-0000-0000-000000000000", {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(410);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("SESSION_EXPIRED");
  });
});

// =========================================================================
// Tests: POST /credentials/batch/:jobId/signatures
// =========================================================================

describe("POST /credentials/batch/:jobId/signatures", () => {
  it("returns 400 for delegated flow batch", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const submitRes = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_DELEGATED_BATCH),
    });
    const submitBody = (await submitRes.json()) as BatchSubmitResponse;

    const sigRes = await app.request(`/credentials/batch/${submitBody.jobId}/signatures`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        signatures: [{ index: 0, signature: "AAAA" }],
      }),
    });

    expect(sigRes.status).toBe(400);
  });

  it("returns 400 for out-of-range index", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const submitRes = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_INTERFACE_BATCH),
    });
    const submitBody = (await submitRes.json()) as BatchSubmitResponse;

    const sigRes = await app.request(`/credentials/batch/${submitBody.jobId}/signatures`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        signatures: [{ index: 99, signature: "AAAA" }],
      }),
    });

    expect(sigRes.status).toBe(400);
  });

  it("returns 410 for non-existent job", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const res = await app.request(
      "/credentials/batch/00000000-0000-0000-0000-000000000000/signatures",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          signatures: [{ index: 0, signature: "AAAA" }],
        }),
      },
    );

    expect(res.status).toBe(410);
  });
});

// =========================================================================
// Tests: Session expiry mid-job
// =========================================================================

describe("Batch session expiry", () => {
  it("returns 410 when job expires between submit and poll", async () => {
    const config = makeTestConfig({
      SESSION_TTL_MS: 1,
      SESSION_SWEEP_INTERVAL_MS: 100000,
      MAX_BATCH_SIZE: 1000,
      DEDI_API_URL: "https://dedi.opencred.test",
    });
    const dediClient = createMockDediClient();
    const { batch, jobStore } = createBatchRoute({
      config,
      authOptions: AUTH_OPTIONS,
      signingKeyProvider,
      dediClient,
    });
    const app = new Hono();
    app.route("/credentials/batch", batch);
    app.onError(errorHandler(logger));

    const token = await makeToken();

    const submitRes = await app.request("/credentials/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_INTERFACE_BATCH),
    });
    const submitBody = (await submitRes.json()) as BatchSubmitResponse;

    // Wait for TTL to expire
    await new Promise((r) => setTimeout(r, 10));

    const pollRes = await app.request(`/credentials/batch/${submitBody.jobId}`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(pollRes.status).toBe(410);

    jobStore.destroy();
  });
});

// =========================================================================
// Tests: POST /credentials/revoke/batch — Batch revocation
// =========================================================================

describe("POST /credentials/revoke/batch", () => {
  it("revokes multiple credentials by hash", async () => {
    const { app, dediClient } = createBatchRevokeApp();

    const res = await app.request("/credentials/revoke/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        hashes: [
          "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
          "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
        ],
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      total: number;
      succeeded: number;
      failed: number;
      results: Array<{ hash: string; status: string }>;
    };

    expect(body.total).toBe(2);
    expect(body.succeeded).toBe(2);
    expect(body.failed).toBe(0);
    expect(dediClient.publishRevocationHash as ReturnType<typeof vi.fn>).toHaveBeenCalledTimes(2);
  });

  it("revokes multiple credentials by computing hashes from credential bodies", async () => {
    const { app } = createBatchRevokeApp();

    const res = await app.request("/credentials/revoke/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credentials: [
          {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            type: ["VerifiableCredential"],
            id: "cred-1",
          },
          {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            type: ["VerifiableCredential"],
            id: "cred-2",
          },
        ],
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { total: number; succeeded: number; failed: number };
    expect(body.total).toBe(2);
    expect(body.succeeded).toBe(2);
  });

  it("handles partial DeDi failure", async () => {
    const { app } = createBatchRevokeApp({ publishFails: true });

    const res = await app.request("/credentials/revoke/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        hashes: ["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"],
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      total: number;
      succeeded: number;
      failed: number;
      results: Array<{ hash: string; status: string; error?: string }>;
    };

    expect(body.total).toBe(1);
    expect(body.failed).toBe(1);
    expect(body.results[0].status).toBe("failed");
    expect(body.results[0].error).toBeDefined();
  });

  it("returns 400 when neither hashes nor credentials provided", async () => {
    const { app } = createBatchRevokeApp();

    const res = await app.request("/credentials/revoke/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid hash format", async () => {
    const { app } = createBatchRevokeApp();

    const res = await app.request("/credentials/revoke/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        hashes: ["not-a-valid-hex-hash"],
      }),
    });

    expect(res.status).toBe(400);
  });
});
