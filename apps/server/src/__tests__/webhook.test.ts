/**
 * Tests for batch webhook delivery.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createHmac } from "node:crypto";
import { deliverWebhook, type WebhookPayload } from "../batch/webhook.js";

// Mock dns resolution
vi.mock("node:dns/promises", () => ({
  resolve: vi.fn().mockResolvedValue(["93.184.216.34"]), // example.com public IP
}));

const dnsPromises = await import("node:dns/promises");

const SAMPLE_PAYLOAD: WebhookPayload = {
  jobId: "test-job-123",
  status: "completed",
  total: 10,
  successCount: 8,
  errorCount: 1,
  skippedCount: 1,
};

const TEST_SECRET = "test-webhook-secret";
const TEST_URL = "https://example.com/webhook";

describe("deliverWebhook", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.mocked(dnsPromises.resolve).mockResolvedValue(["93.184.216.34"]);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  function mockFetch(...responses: Array<Response | Error>): Array<Array<unknown>> {
    const calls: Array<Array<unknown>> = [];
    let idx = 0;
    globalThis.fetch = ((...args: unknown[]) => {
      calls.push(args);
      const resp = responses[idx++];
      if (resp instanceof Error) return Promise.reject(resp);
      return Promise.resolve(resp);
    }) as typeof fetch;
    return calls;
  }

  it("computes correct HMAC-SHA256 signature", async () => {
    const calls = mockFetch(new Response("ok", { status: 200 }));

    await deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET);

    expect(calls).toHaveLength(1);
    const headers = (calls[0][1] as RequestInit).headers as Record<string, string>;

    const expectedBody = JSON.stringify(SAMPLE_PAYLOAD);
    const expectedSig = `sha256=${createHmac("sha256", TEST_SECRET).update(expectedBody).digest("hex")}`;

    expect(headers["X-OpenCred-Signature"]).toBe(expectedSig);
    expect(headers["X-OpenCred-Event"]).toBe("batch.completed");
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers["User-Agent"]).toBe("OpenCred-Server");
  });

  it("uses unsigned marker when secret is empty", async () => {
    const calls = mockFetch(new Response("ok", { status: 200 }));

    await deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, "");

    const headers = (calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers["X-OpenCred-Signature"]).toBe("sha256=unsigned");
  });

  it("retries on failure and succeeds on third attempt", async () => {
    const calls = mockFetch(
      new Error("network error"),
      new Response("error", { status: 500 }),
      new Response("ok", { status: 200 }),
    );

    await deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET);

    expect(calls).toHaveLength(3);
  });

  it("throws after all retries exhausted", async () => {
    mockFetch(
      new Response("error", { status: 500 }),
      new Response("error", { status: 502 }),
      new Response("error", { status: 503 }),
    );

    await expect(deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET)).rejects.toThrow(
      "Webhook returned HTTP 503",
    );
  });

  it("rejects non-HTTPS URLs", async () => {
    const calls = mockFetch();

    await expect(
      deliverWebhook("http://example.com/webhook", SAMPLE_PAYLOAD, TEST_SECRET),
    ).rejects.toThrow("Webhook URL must use HTTPS");

    expect(calls).toHaveLength(0);
  });

  it("rejects webhook URLs that resolve to private IPs", async () => {
    vi.mocked(dnsPromises.resolve).mockResolvedValue(["192.168.1.1"]);
    const calls = mockFetch();

    await expect(deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET)).rejects.toThrow(
      "Webhook URL resolves to private IP",
    );

    expect(calls).toHaveLength(0);
  });

  it("rejects webhook URLs that resolve to loopback IPs", async () => {
    vi.mocked(dnsPromises.resolve).mockResolvedValue(["127.0.0.1"]);

    await expect(deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET)).rejects.toThrow(
      "Webhook URL resolves to private IP",
    );
  });

  it("payload shape contains only metadata, never credential content", () => {
    const payload: WebhookPayload = {
      jobId: "job-1",
      status: "completed",
      total: 5,
      successCount: 5,
      errorCount: 0,
      skippedCount: 0,
    };

    const serialized = JSON.stringify(payload);
    const keys = Object.keys(payload);

    // Only allowed keys
    expect(keys).toEqual(["jobId", "status", "total", "successCount", "errorCount", "skippedCount"]);

    // Must not contain anything that looks like credential content
    expect(serialized).not.toContain("credentialSubject");
    expect(serialized).not.toContain("proof");
    expect(serialized).not.toContain("verifiableCredential");
  });

  it("succeeds on first attempt with 2xx response", async () => {
    mockFetch(new Response("accepted", { status: 202 }));

    await expect(deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET)).resolves.toBeUndefined();
  });
});
