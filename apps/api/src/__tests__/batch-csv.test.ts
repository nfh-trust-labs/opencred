import { describe, it, expect, vi } from "vitest";
import { createSign, generateKeyPairSync } from "node:crypto";
import { Hono } from "hono";
import { createCapabilityToken } from "@opencred/auth";
import { LocalSigningKeyProvider } from "@opencred/crypto";
import type { DeDiClient } from "@opencred/dedi-client";
import type { DelegationCertificate } from "@opencred/delegation";
import { createBatchRoute } from "../routes/batch.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestConfig, makeTestLogger } from "./helpers.js";

// -------------------------------------------------------------------------
// Test infrastructure
// -------------------------------------------------------------------------

const TEST_SECRET = new TextEncoder().encode("test-secret-key-that-is-at-least-32-bytes-long!!");
const logger = makeTestLogger();

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
): DeDiClient {
  return {
    resolveDelegation: vi.fn().mockImplementation(async (id: string) => {
      if (!delegation) {
        throw new Error(`Delegation ${id} not found`);
      }
      return { id, certificate: delegation };
    }),
    registerDelegation: vi.fn().mockResolvedValue({}),
    queryRevocationHash: vi.fn().mockResolvedValue({ revoked: false, hash: "mock-hash" }),
    publishRevocationHash: vi.fn().mockResolvedValue({
      hash: "mock",
      revoked: true,
      revokedAt: new Date().toISOString(),
    }),
    resolveDID: vi.fn().mockResolvedValue({ did: "did:web:example" }),
  } as unknown as DeDiClient;
}

// -------------------------------------------------------------------------
// App factory
// -------------------------------------------------------------------------

function createBatchApp(options?: { maxBatchSize?: number }) {
  const config = makeTestConfig({
    DEDI_API_URL: "https://dedi.opencred.test",
    MAX_BATCH_SIZE: options?.maxBatchSize ?? 1000,
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
  return { app, jobStore, dediClient };
}

// -------------------------------------------------------------------------
// CSV test helpers
// -------------------------------------------------------------------------

function makeCsvFormData(csvContent: string, fields: Record<string, string>): FormData {
  const formData = new FormData();
  const blob = new Blob([csvContent], { type: "text/csv" });
  formData.append("file", blob, "batch.csv");
  for (const [key, value] of Object.entries(fields)) {
    formData.append(key, value);
  }
  return formData;
}

const INTERFACE_CSV_FIELDS = {
  schema: "education",
  signingFlow: "interface",
  issuer: "did:web:university.example",
  publicKey: issuerPublicKeyId,
  revocationRegistryUrl: "https://dedi.example/revocations/university.example/reg",
  validFrom: "2026-01-01T00:00:00Z",
};

const DELEGATED_CSV_FIELDS = {
  schema: "education",
  signingFlow: "delegated",
  delegationId: "urn:uuid:delegation-1",
  validFrom: "2026-01-01T00:00:00Z",
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
  }>;
}

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
// Tests: POST /credentials/batch/csv — CSV upload
// =========================================================================

describe("POST /credentials/batch/csv", () => {
  it("returns 401 without auth token", async () => {
    const { app } = createBatchApp();
    const csv = "name,degree,institution,dateConferred\nJane Doe,BSc,Example Uni,2025-06-15\n";
    const formData = makeCsvFormData(csv, INTERFACE_CSV_FIELDS);

    const res = await app.request("/credentials/batch/csv", {
      method: "POST",
      body: formData,
    });
    expect(res.status).toBe(401);
  });

  it("returns 400 when file is missing", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const formData = new FormData();
    formData.append("schema", "education");
    formData.append("signingFlow", "interface");
    formData.append("validFrom", "2026-01-01T00:00:00Z");
    formData.append("issuer", "did:web:university.example");
    formData.append("publicKey", issuerPublicKeyId);
    formData.append("revocationRegistryUrl", "https://dedi.example/rev");

    const res = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("file");
  });

  it("returns 400 for malformed CSV", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    // Malformed CSV with inconsistent quoting
    const malformedCsv = 'name,degree\n"unclosed quote,BSc\n';
    const formData = makeCsvFormData(malformedCsv, INTERFACE_CSV_FIELDS);

    const res = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("parse CSV");
  });

  it("returns 400 for empty CSV (no data rows)", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const emptyCsv = "name,degree,institution,dateConferred\n";
    const formData = makeCsvFormData(emptyCsv, INTERFACE_CSV_FIELDS);

    const res = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("no data rows");
  });

  it("returns 400 when schema field is missing", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const csv = "name,degree,institution,dateConferred\nJane Doe,BSc,Example Uni,2025-06-15\n";
    const { schema: _schema, ...fieldsWithoutSchema } = INTERFACE_CSV_FIELDS;
    const formData = makeCsvFormData(csv, fieldsWithoutSchema);

    const res = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("schema");
  });

  it("returns 400 when CSV exceeds MAX_BATCH_SIZE", async () => {
    const { app } = createBatchApp({ maxBatchSize: 2 });
    const token = await makeToken();

    const csv =
      "name,degree,institution,dateConferred\n" +
      "Jane Doe,BSc,Example Uni,2025-06-15\n" +
      "John Smith,MSc,Example Uni,2025-06-15\n" +
      "Alice Brown,PhD,Example Uni,2025-06-15\n";
    const formData = makeCsvFormData(csv, INTERFACE_CSV_FIELDS);

    const res = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("exceeding maximum");
  });

  it("rejects batch when CSV rows have missing required columns", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    // Missing 'institution' and 'dateConferred' columns
    const csv = "name,degree\nJane Doe,BSc\nJohn Smith,MSc\n";
    const formData = makeCsvFormData(csv, INTERFACE_CSV_FIELDS);

    const res = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });

    expect(res.status).toBe(202);
    const body = (await res.json()) as BatchSubmitResponse;
    expect(body.status).toBe("failed");
    expect(body.failed).toBeGreaterThan(0);
  });

  it("reports per-row validation errors with line numbers", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    // Row 1 (line 2): valid. Row 2 (line 3): missing required fields
    const csv =
      "name,degree,institution,dateConferred\n" +
      "Jane Doe,BSc,Example Uni,2025-06-15\n" +
      "John Smith,,,\n";
    const formData = makeCsvFormData(csv, INTERFACE_CSV_FIELDS);

    const submitRes = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });

    const submitBody = (await submitRes.json()) as BatchSubmitResponse;
    expect(submitBody.status).toBe("failed");

    // Get results with row-level errors
    const resultsRes = await app.request(`/credentials/batch/${submitBody.jobId}/results`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    const resultsBody = (await resultsRes.json()) as BatchResultsResponse;
    const failedRow = resultsBody.results.find((r) => r.status === "failed");
    expect(failedRow).toBeDefined();
    // Error message should reference the CSV line number (row index + 2 for header)
    expect(failedRow!.error).toContain("Row");
  });

  it("maps CSV columns to credentialSubject fields successfully (interface signing)", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const csv =
      "name,degree,institution,dateConferred\n" +
      "Jane Doe,Bachelor of Science,Example University,2025-06-15\n" +
      "John Smith,Master of Arts,Example University,2025-06-15\n";
    const formData = makeCsvFormData(csv, INTERFACE_CSV_FIELDS);

    const submitRes = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });

    expect(submitRes.status).toBe(202);
    const submitBody = (await submitRes.json()) as BatchSubmitResponse;
    expect(submitBody.status).toBe("awaiting_signatures");
    expect(submitBody.total).toBe(2);

    // Get results to verify signing data was prepared
    const resultsRes = await app.request(`/credentials/batch/${submitBody.jobId}/results`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    const resultsBody = (await resultsRes.json()) as BatchResultsResponse;
    expect(resultsBody.results).toHaveLength(2);
    for (const row of resultsBody.results) {
      expect(row.status).toBe("awaiting_signature");
      expect(row.dataToSign).toBeDefined();
    }
  });

  it("completes CSV delegated signing round-trip", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const csv =
      "name,degree,institution,dateConferred\n" +
      "Jane Doe,Bachelor of Science,Example University,2025-06-15\n" +
      "John Smith,Master of Arts,Example University,2025-06-15\n";
    const formData = makeCsvFormData(csv, DELEGATED_CSV_FIELDS);

    const submitRes = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });

    expect(submitRes.status).toBe(202);
    const submitBody = (await submitRes.json()) as BatchSubmitResponse;
    expect(submitBody.status).toBe("completed");
    expect(submitBody.succeeded).toBe(2);

    // Get results
    const resultsRes = await app.request(`/credentials/batch/${submitBody.jobId}/results`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    const resultsBody = (await resultsRes.json()) as BatchResultsResponse;
    for (const row of resultsBody.results) {
      expect(row.status).toBe("issued");
      expect(row.credential).toBeDefined();
    }
  });

  it("completes CSV interface signing full round-trip (submit CSV → sign → package)", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const csv =
      "name,degree,institution,dateConferred\n" +
      "Jane Doe,Bachelor of Science,Example University,2025-06-15\n";
    const formData = makeCsvFormData(csv, INTERFACE_CSV_FIELDS);

    // Step 1: Submit CSV
    const submitRes = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
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

    // Step 3: Sign
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
    expect(sigBody.succeeded).toBe(1);

    // Step 5: Verify final credential
    const finalRes = await app.request(`/credentials/batch/${jobId}/results`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    const finalBody = (await finalRes.json()) as BatchResultsResponse;
    const vc = finalBody.results[0].credential!;
    expect(vc["@context"]).toContain("https://www.w3.org/ns/credentials/v2");
    expect((vc.proof as Record<string, unknown>)?.type).toBe("DataIntegrityProof");
  });

  it("allows per-row validFrom/validUntil override via CSV columns", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const csv =
      "name,degree,institution,dateConferred,validFrom,validUntil\n" +
      "Jane Doe,Bachelor of Science,Example University,2025-06-15,2026-02-01T00:00:00Z,2027-02-01T00:00:00Z\n" +
      "John Smith,Master of Arts,Example University,2025-06-15,2026-03-01T00:00:00Z,\n";
    const formData = makeCsvFormData(csv, DELEGATED_CSV_FIELDS);

    const submitRes = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });

    expect(submitRes.status).toBe(202);
    const submitBody = (await submitRes.json()) as BatchSubmitResponse;
    expect(submitBody.status).toBe("completed");
    expect(submitBody.succeeded).toBe(2);

    // Check that per-row dates were used
    const resultsRes = await app.request(`/credentials/batch/${submitBody.jobId}/results`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    const resultsBody = (await resultsRes.json()) as BatchResultsResponse;
    const cred0 = resultsBody.results[0].credential!;
    const cred1 = resultsBody.results[1].credential!;

    expect(cred0.validFrom).toBe("2026-02-01T00:00:00Z");
    expect(cred0.validUntil).toBe("2027-02-01T00:00:00Z");
    expect(cred1.validFrom).toBe("2026-03-01T00:00:00Z");
    // Second row had empty validUntil — should not be set
    expect(cred1.validUntil).toBeUndefined();
  });

  it("handles CSV with mixed valid/invalid rows", async () => {
    const { app } = createBatchApp();
    const token = await makeToken();

    const csv =
      "name,degree,institution,dateConferred\n" +
      "Jane Doe,BSc,Example Uni,2025-06-15\n" +
      "Invalid Row,,,\n" +
      "John Smith,MSc,Example Uni,2025-06-15\n";
    const formData = makeCsvFormData(csv, INTERFACE_CSV_FIELDS);

    const res = await app.request("/credentials/batch/csv", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });

    expect(res.status).toBe(202);
    const body = (await res.json()) as BatchSubmitResponse;
    // Two-phase: validation fails → entire batch rejected
    expect(body.status).toBe("failed");
    expect(body.failed).toBe(1);
    expect(body.total).toBe(3);
  });
});
