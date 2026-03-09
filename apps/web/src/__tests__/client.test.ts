import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { OpenCredClient } from "../api/client";

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

function jsonResponse(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
  });
}

describe("OpenCredClient", () => {
  it("sends build request with auth header", async () => {
    const client = new OpenCredClient("http://localhost:3000", "test-token");
    mockFetch.mockReturnValue(
      jsonResponse(
        {
          sessionId: "abc-123",
          unsignedCredential: {},
          dataToSign: "AQID",
          proofConfig: {},
        },
        201,
      ),
    );

    const res = await client.buildCredential({
      schema: "education",
      issuer: "did:key:z123",
      publicKey: "pk-id",
      credentialSubject: { name: "Alice" },
      validFrom: "2024-01-01T00:00:00Z",
      revocationRegistryUrl: "https://example.com/rev",
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/build");
    expect(opts.headers["Authorization"]).toBe("Bearer test-token");
    expect(res.sessionId).toBe("abc-123");
  });

  it("sends package request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({
        credential: { "@context": [] },
        formats: { jsonld: { "@context": [] } },
      }),
    );

    const res = await client.packageCredential({
      sessionId: "abc-123",
      signature: "c2lnbmF0dXJl",
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/package");
    expect(res.credential).toBeDefined();
  });

  it("sends verify request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({
        status: "VALID",
        checks: {
          signature: { passed: true },
          expiry: { passed: true },
          revocation: { passed: true },
        },
      }),
    );

    const res = await client.verifyCredential({ "@context": [], type: ["VerifiableCredential"] });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/verify");
    expect(res.status).toBe("VALID");
  });

  it("throws on API error responses", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({ error: { code: "VALIDATION_ERROR", message: "Schema not found" } }, 400),
    );

    await expect(client.verifyCredential({})).rejects.toThrow("Schema not found");
  });

  it("throws a readable error when API returns non-JSON response", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: false,
        status: 404,
        statusText: "Not Found",
        json: () => Promise.reject(new SyntaxError("Unexpected token")),
      }),
    );

    await expect(client.verifyCredential({})).rejects.toThrow("Request failed: 404 Not Found");
  });

  it("omits Authorization header when no token provided", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(jsonResponse({ status: "VALID", checks: {} }));

    await client.verifyCredential({});

    const [, opts] = mockFetch.mock.calls[0];
    expect(opts.headers["Authorization"]).toBeUndefined();
  });

  // --- New endpoint tests ---

  it("sends onboardDomainVerify request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({
        challengeId: "ch-1",
        challengeType: "dns",
        challengeValue: "val",
        instructions: "Add TXT",
      }),
    );

    const res = await client.onboardDomainVerify("example.com", "dns");

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/onboarding/domain-verify");
    expect(JSON.parse(opts.body)).toEqual({ domain: "example.com", method: "dns" });
    expect(res.challengeId).toBe("ch-1");
  });

  it("sends onboardDomainConfirm request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(jsonResponse({ verified: true, issuerId: "iss-2" }));

    const res = await client.onboardDomainConfirm("ch-1");

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/onboarding/domain-verify/confirm");
    expect(JSON.parse(opts.body)).toEqual({ challengeId: "ch-1" });
    expect(res.verified).toBe(true);
  });

  it("sends onboardBusinessVc request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({
        delegationId: "del-1",
        issuerId: "iss-3",
        capabilityToken: "cap-tok",
        scope: ["education"],
        validFrom: "2024-01-01",
        validUntil: "2025-01-01",
      }),
    );

    const vc = { type: "BusinessCredential" };
    const res = await client.onboardBusinessVc(vc, "delegated", "pub-key");

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/onboarding/business-vc");
    expect(JSON.parse(opts.body)).toEqual({
      businessCredential: vc,
      signingPreference: "delegated",
      publicKey: "pub-key",
    });
    expect(res.delegationId).toBe("del-1");
  });

  it("sends issueDelegated request", async () => {
    const client = new OpenCredClient("http://localhost:3000", "tok");
    mockFetch.mockReturnValue(jsonResponse({ credential: { type: "VC" }, credentialHash: "h-1" }));

    const res = await client.issueDelegated("del-1", "education", { name: "Alice" });

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/issue-delegated");
    expect(JSON.parse(opts.body)).toEqual({
      delegationId: "del-1",
      schema: "education",
      credentialSubject: { name: "Alice" },
    });
    expect(res.credentialHash).toBe("h-1");
  });

  it("sends computeRevocationHash request with credential", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(jsonResponse({ hash: "computed-hash-abc" }));

    const cred = { "@context": [], type: "VC" };
    const res = await client.computeRevocationHash(cred);

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/revocation-hash");
    expect(JSON.parse(opts.body)).toEqual({ credential: cred });
    expect(res.hash).toBe("computed-hash-abc");
  });

  it("sends computeRevocationHashBatch request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    const creds = [{ "@context": [], type: "VC1" }, { "@context": [], type: "VC2" }];
    mockFetch.mockReturnValue(
      jsonResponse({
        hashes: [
          { hash: "h1", index: 0 },
          { hash: "h2", index: 1 },
        ],
      }),
    );

    const res = await client.computeRevocationHashBatch(creds);

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/revocation-hash/batch");
    expect(JSON.parse(opts.body)).toEqual({ credentials: creds });
    expect(res.hashes).toHaveLength(2);
    expect(res.hashes[0].hash).toBe("h1");
  });

  it("sends batchSubmit request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({ jobId: "job-1", totalCredentials: 10, status: "pending" }),
    );

    const res = await client.batchSubmit({
      schema: "education",
      signingFlow: "delegated",
      credentials: [{ name: "Alice" }],
      delegationId: "del-1",
    });

    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/batch");
    expect(res.jobId).toBe("job-1");
  });

  it("sends batchStatus GET request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({
        jobId: "job-1",
        status: "processing",
        progress: 0.5,
        totalCredentials: 10,
        processedCredentials: 5,
        failedCredentials: 0,
      }),
    );

    const res = await client.batchStatus("job-1");

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/batch/job-1");
    expect(opts.method).toBe("GET");
    expect(res.status).toBe("processing");
  });

  it("sends batchResults GET request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({ jobId: "job-1", results: [{ index: 0, status: "success" }] }),
    );

    const res = await client.batchResults("job-1");

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/batch/job-1/results");
    expect(opts.method).toBe("GET");
    expect(res.results).toHaveLength(1);
  });

  it("sends batchSignatures POST request", async () => {
    const client = new OpenCredClient("http://localhost:3000");
    mockFetch.mockReturnValue(
      jsonResponse({ processed: 1, results: [{ index: 0, status: "success" }] }),
    );

    const res = await client.batchSignatures("job-1", [{ index: 0, signature: "sig-abc" }]);

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/batch/job-1/signatures");
    expect(JSON.parse(opts.body)).toEqual({ signatures: [{ index: 0, signature: "sig-abc" }] });
    expect(res.processed).toBe(1);
  });

  it("sends batchSubmitCsv with FormData", async () => {
    const client = new OpenCredClient("http://localhost:3000", "tok");
    mockFetch.mockReturnValue(
      jsonResponse({ jobId: "job-2", totalCredentials: 3, status: "pending" }),
    );

    const formData = new FormData();
    formData.append("file", new Blob(["test"]), "test.csv");

    const res = await client.batchSubmitCsv(formData);

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:3000/credentials/batch/csv");
    expect(opts.body).toBe(formData);
    expect(opts.headers["Authorization"]).toBe("Bearer tok");
    // FormData should not have Content-Type header (browser sets it with boundary)
    expect(opts.headers["Content-Type"]).toBeUndefined();
    expect(res.jobId).toBe("job-2");
  });
});
