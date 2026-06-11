import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import type { Hono } from "hono";
import { generateTestKey, createTestApp } from "./helpers.js";
import type { TestKeyPair } from "./helpers.js";
import { setActiveSigner } from "../../signing/key-manager.js";
import { verifyCredential } from "@opencred/verification";
import type {
  JWK,
  DIDResolver,
  DIDResolutionResult,
  DIDDocument,
  VerificationMethod,
} from "@opencred/did";

let app: Hono;
let testKey: TestKeyPair;

function makeResolver(did: string, vmId: string, jwk: JWK): DIDResolver {
  const vm: VerificationMethod = {
    id: vmId,
    type: "JsonWebKey",
    controller: did,
    publicKeyJwk: jwk,
  };
  return {
    resolve: async (input: string): Promise<DIDResolutionResult> => {
      if (input !== did) {
        return {
          didDocument: null,
          didResolutionMetadata: { error: "notFound" },
          didDocumentMetadata: {},
        };
      }
      return {
        didDocument: {
          "@context": "https://www.w3.org/ns/did/v1",
          id: did,
          verificationMethod: [vm],
          assertionMethod: [vmId],
        } as DIDDocument,
        didResolutionMetadata: {},
        didDocumentMetadata: {},
      };
    },
  };
}

async function pollUntilDone(
  app: Hono,
  jobId: string,
  maxMs: number = 10_000,
): Promise<Record<string, unknown>> {
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    const res = await app.request(`/v1/credentials/batch/${jobId}`);
    const body = (await res.json()) as Record<string, unknown>;
    if (body.running === false) return body;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`Batch job ${jobId} did not finish within ${maxMs}ms`);
}

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);
});

describe("batch real signing (cross-package integration)", () => {
  const csvContent = [
    "name,role,validFrom",
    "Alice,Medical Practitioner,2025-06-01T00:00:00Z",
    "Bob,Registered Nurse,2025-06-01T00:00:00Z",
    "Carol,Pharmacist,2025-06-01T00:00:00Z",
  ].join("\n");

  const issuerDid = () => testKey.signer.id.split("#")[0];
  const signerVmId = () => testKey.signer.id;

  it("3-row batch vc-jwt: issue, poll, verify one credential", async () => {
    const startRes = await app.request("/v1/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent,
        schemaId: "functional-identity/v1",
        issuerDid: issuerDid(),
        validFrom: "2025-06-01T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(startRes.status).toBe(202);
    const startBody = (await startRes.json()) as Record<string, unknown>;
    expect(startBody.validCount).toBe(3);
    const jobId = startBody.jobId as string;

    const progress = await pollUntilDone(app, jobId);
    expect(progress.completed).toBe(3);
    expect(progress.successCount).toBe(3);
    expect(progress.errorCount).toBe(0);

    const resultsRes = await app.request(`/v1/credentials/batch/${jobId}/results`);
    expect(resultsRes.status).toBe(200);
    const resultsBody = (await resultsRes.json()) as {
      results: Array<Record<string, unknown>>;
    };
    const successRows = resultsBody.results.filter((r) => r.status === "success");
    expect(successRows.length).toBe(3);

    const firstCred = successRows[0].credential as Record<string, unknown>;
    expect(firstCred).toBeDefined();
    const proof = firstCred.proof as Record<string, unknown>;
    expect(proof).toBeDefined();
    const jwt = proof.jwt as string;
    expect(typeof jwt).toBe("string");

    const jwk = testKey.publicKey.export({ format: "jwk" }) as JWK;
    const verifyResult = await verifyCredential(jwt, {
      didResolver: makeResolver(issuerDid(), signerVmId(), jwk),
    });
    expect(verifyResult.verified).toBe(true);
    expect(verifyResult.code).toBe("VALID");
  });

  it("data-integrity batch: safe-mode rejects undefined JSON-LD terms", async () => {
    // Data Integrity proofs canonicalize the credential using JSON-LD safe mode.
    // Fields not defined in the @context (like "role" from functional-identity)
    // are rejected to prevent the silent-field-drop attack. This is correct
    // security behavior: VC-JWT is the right format for schemas with custom fields
    // that lack a JSON-LD context definition.
    const startRes = await app.request("/v1/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent,
        schemaId: "functional-identity/v1",
        issuerDid: issuerDid(),
        validFrom: "2025-06-01T00:00:00Z",
        proofFormat: "data-integrity",
      }),
    });
    expect(startRes.status).toBe(202);
    const startBody = (await startRes.json()) as Record<string, unknown>;
    const jobId = startBody.jobId as string;

    const progress = await pollUntilDone(app, jobId);
    expect(progress.completed).toBe(3);
    expect(progress.errorCount).toBe(3);
    expect(progress.successCount).toBe(0);

    const resultsRes = await app.request(`/v1/credentials/batch/${jobId}/results`);
    expect(resultsRes.status).toBe(200);
    const resultsBody = (await resultsRes.json()) as {
      results: Array<Record<string, unknown>>;
    };
    const errorRows = resultsBody.results.filter((r) => r.status === "error");
    expect(errorRows.length).toBe(3);
    for (const row of errorRows) {
      expect(row.error).toContain("Safe mode validation error");
    }
  });

  it("batch progress reports accurate counts (completed === total)", async () => {
    const startRes = await app.request("/v1/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent,
        schemaId: "functional-identity/v1",
        issuerDid: issuerDid(),
        validFrom: "2025-06-01T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    const { jobId } = (await startRes.json()) as { jobId: string };

    const progress = await pollUntilDone(app, jobId);
    expect(progress.total).toBe(3);
    expect(progress.completed).toBe(progress.total);
    expect(progress.running).toBe(false);
    expect(
      (progress.successCount as number) +
        (progress.errorCount as number) +
        (progress.skippedCount as number),
    ).toBe(progress.total);
  });
});
