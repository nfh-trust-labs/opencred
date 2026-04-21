/**
 * Scale test smoke tests.
 *
 * These verify that the test payloads and concurrent request patterns work
 * correctly against the Hono test app. They do NOT measure performance —
 * that is the job of the external `scripts/scale-test.ts` script which
 * uses autocannon against a real HTTP server.
 *
 * The purpose here is to catch payload/schema drift early so that when a
 * developer runs the full scale test they do not waste time debugging
 * broken payloads.
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { createTestApp, generateTestKey, VALID_ISSUE_REQUEST } from "../helpers.js";
import { setActiveSigner } from "../../signing/key-manager.js";
import type { Hono } from "hono";
import type { TestKeyPair } from "../helpers.js";

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);
});

// ---------------------------------------------------------------------------
// Payload validation — ensure every scale test payload produces a 200
// ---------------------------------------------------------------------------

describe("scale test payload validation", () => {
  it("health endpoint returns 200", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("ok");
  });

  it("issue payload produces a signed credential", async () => {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(VALID_ISSUE_REQUEST),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { credential: unknown; proofFormat: string };
    expect(body.proofFormat).toBe("vc-jwt");
    expect(body.credential).toBeDefined();
  });

  it("verify payload roundtrips with a data-integrity credential", async () => {
    // Issue with data-integrity for a self-contained verifiable credential
    const issueRes = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        issuerDid: testKey.signer.id.split("#")[0],
        proofFormat: "data-integrity",
      }),
    });
    expect(issueRes.status).toBe(200);
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };

    // Verify it
    const verifyRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: JSON.stringify(issued.credential) }),
    });
    expect(verifyRes.status).toBe(200);
    const result = (await verifyRes.json()) as { valid: boolean };
    expect(result.valid).toBe(true);
  });

  it("batch CSV payload is accepted", async () => {
    const csvContent = [
      "name,role,validFrom",
      "Alice,Medical Practitioner,2025-06-01T00:00:00Z",
      "Bob,Medical Practitioner,2025-06-01T00:00:00Z",
      "Carol,Medical Practitioner,2025-06-01T00:00:00Z",
    ].join("\n");

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(res.status).toBe(202);
    const body = (await res.json()) as { jobId: string; validCount: number; totalCount: number };
    expect(body.jobId).toBeDefined();
    expect(body.validCount).toBe(3);
    expect(body.totalCount).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Concurrent request simulation — verify no race conditions
// ---------------------------------------------------------------------------

describe("concurrent request simulation", () => {
  it("handles 20 concurrent issue requests without errors", async () => {
    const concurrency = 20;
    const promises = Array.from({ length: concurrency }, () =>
      app.request("/credentials/issue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(VALID_ISSUE_REQUEST),
      }),
    );

    const responses = await Promise.all(promises);
    const statuses = responses.map((r) => r.status);
    expect(statuses.every((s) => s === 200)).toBe(true);
  });

  it("handles 20 concurrent health requests without errors", async () => {
    const concurrency = 20;
    const promises = Array.from({ length: concurrency }, () => app.request("/health"));

    const responses = await Promise.all(promises);
    const statuses = responses.map((r) => r.status);
    expect(statuses.every((s) => s === 200)).toBe(true);
  });

  it("handles mixed concurrent requests (issue + health + verify)", async () => {
    // First issue a credential to use for verification
    const issueRes = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        issuerDid: testKey.signer.id.split("#")[0],
        proofFormat: "data-integrity",
      }),
    });
    expect(issueRes.status).toBe(200);
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };
    const verifyBody = JSON.stringify({ credential: JSON.stringify(issued.credential) });

    // Now fire a mixed workload concurrently
    const promises: Array<Response | Promise<Response>> = [];

    // 7 verify requests
    for (let i = 0; i < 7; i++) {
      promises.push(
        app.request("/credentials/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: verifyBody,
        }),
      );
    }

    // 2 issue requests
    for (let i = 0; i < 2; i++) {
      promises.push(
        app.request("/credentials/issue", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(VALID_ISSUE_REQUEST),
        }),
      );
    }

    // 1 health request
    promises.push(app.request("/health"));

    const responses = await Promise.all(promises);
    const statuses = responses.map((r) => r.status);
    expect(statuses.every((s) => s === 200)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Batch CSV generation — verify different row counts
// ---------------------------------------------------------------------------

describe("batch CSV row-count scaling", () => {
  for (const rowCount of [10, 50]) {
    it(`accepts a batch with ${rowCount} rows`, async () => {
      const header = "name,role,validFrom";
      const rows = [header];
      for (let i = 0; i < rowCount; i++) {
        rows.push(`Person ${i},Medical Practitioner,2025-06-15T00:00:00Z`);
      }

      const res = await app.request("/credentials/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          csvContent: rows.join("\n"),
          schemaId: "functional-identity/v1",
          issuerDid: testKey.signer.id.split("#")[0],
          validFrom: "2025-06-15T00:00:00Z",
          proofFormat: "vc-jwt",
        }),
      });
      expect(res.status).toBe(202);
      const body = (await res.json()) as { validCount: number; totalCount: number };
      expect(body.validCount).toBe(rowCount);
      expect(body.totalCount).toBe(rowCount);
    });
  }
});
