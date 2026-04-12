/**
 * Metrics endpoint and instrumentation tests.
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { createTestApp, generateTestKey, VALID_ISSUE_REQUEST } from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import type { Hono } from "hono";
import type { TestKeyPair } from "./helpers.js";

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
// GET /metrics
// ---------------------------------------------------------------------------

describe("GET /metrics", () => {
  it("returns 200 with Prometheus text format", async () => {
    const res = await app.request("/metrics");
    expect(res.status).toBe(200);

    const contentType = res.headers.get("content-type") ?? "";
    expect(contentType).toContain("text/plain");

    const body = await res.text();
    // Default process metrics should be present
    expect(body).toContain("process_cpu");
    // Custom metrics should be registered
    expect(body).toContain("http_requests_total");
    expect(body).toContain("http_request_duration_seconds");
    expect(body).toContain("opencred_credentials_issued_total");
    expect(body).toContain("opencred_credentials_verified_total");
    expect(body).toContain("opencred_batch_jobs_total");
  });

  it("is accessible at /v1/metrics", async () => {
    const res = await app.request("/v1/metrics");
    expect(res.status).toBe(200);

    const body = await res.text();
    expect(body).toContain("http_requests_total");
  });
});

// ---------------------------------------------------------------------------
// Metrics auth bypass
// ---------------------------------------------------------------------------

describe("Metrics auth bypass", () => {
  it("GET /metrics does not require auth", async () => {
    const authApp = createTestApp({ apiKey: "test-key-metrics" });
    setActiveSigner(testKey.signer);

    // Request without Authorization header
    const res = await authApp.request("/metrics");
    expect(res.status).toBe(200);
  });

  it("GET /v1/metrics does not require auth", async () => {
    const authApp = createTestApp({ apiKey: "test-key-metrics" });
    setActiveSigner(testKey.signer);

    const res = await authApp.request("/v1/metrics");
    expect(res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// HTTP request metrics recording
// ---------------------------------------------------------------------------

describe("HTTP request metrics recording", () => {
  it("records HTTP request metrics after a request", async () => {
    // Make a request to trigger metrics recording
    await app.request("/health");

    // Check that the metrics endpoint now contains recorded data
    const res = await app.request("/metrics");
    const body = await res.text();

    // Should have recorded the /health request
    expect(body).toContain("http_requests_total");
    expect(body).toContain("http_request_duration_seconds");
  });
});

// ---------------------------------------------------------------------------
// Business metrics instrumentation
// ---------------------------------------------------------------------------

describe("Business metrics instrumentation", () => {
  it("increments credentials_issued counter after successful issuance", async () => {
    // Issue a credential
    const issueRes = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(VALID_ISSUE_REQUEST),
    });
    expect(issueRes.status).toBe(200);

    // Check metrics
    const metricsRes = await app.request("/metrics");
    const body = await metricsRes.text();
    expect(body).toContain('opencred_credentials_issued_total{proof_format="vc-jwt"');
  });
});
