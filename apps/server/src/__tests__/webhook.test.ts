/**
 * Tests for batch webhook delivery.
 *
 * Delivery goes through `fetchWithPinnedIp`, so the SSRF/DNS-rebinding
 * assertions here are about WHAT IS PINNED (the full validated address set)
 * and about DNS never being consulted a second time — not about a rewritten
 * URL. The previous implementation rewrote the URL to the IP and sent a
 * `Host:` header, which broke TLS certificate validation
 * (ERR_TLS_CERT_ALTNAME_INVALID) against every real HTTPS endpoint.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createHmac } from "node:crypto";

// Mock dns resolution
vi.mock("node:dns/promises", () => ({
  resolve: vi.fn().mockResolvedValue(["93.184.216.34"]), // example.com public IP
}));

// Mock only the pinned fetch; everything else in @opencred/shared stays real
// (notably `isPrivateIP`, which the SSRF check depends on).
vi.mock("@opencred/shared", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@opencred/shared")>();
  return { ...actual, fetchWithPinnedIp: vi.fn() };
});

const dnsPromises = await import("node:dns/promises");
const shared = await import("@opencred/shared");
const { deliverWebhook } = await import("../batch/webhook.js");
type WebhookPayload = import("../batch/webhook.js").WebhookPayload;

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

/** Arguments of one `fetchWithPinnedIp` call. */
type PinnedCall = [string | URL, readonly string[], Record<string, unknown>];

describe("deliverWebhook", () => {
  beforeEach(() => {
    vi.mocked(dnsPromises.resolve).mockReset();
    vi.mocked(dnsPromises.resolve).mockResolvedValue(["93.184.216.34"]);
    vi.mocked(shared.fetchWithPinnedIp).mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /** Queue up responses (or errors) for successive pinned-fetch calls. */
  function mockPinnedFetch(...responses: Array<Response | Error>): PinnedCall[] {
    const calls: PinnedCall[] = [];
    let idx = 0;
    vi.mocked(shared.fetchWithPinnedIp).mockImplementation(
      (url, addresses, options): Promise<Response> => {
        calls.push([url, addresses, (options ?? {}) as Record<string, unknown>]);
        const resp = responses[idx++];
        if (resp instanceof Error) return Promise.reject(resp);
        return Promise.resolve(resp);
      },
    );
    return calls;
  }

  it("computes correct HMAC-SHA256 signature", async () => {
    const calls = mockPinnedFetch(new Response("ok", { status: 200 }));

    await deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET);

    expect(calls).toHaveLength(1);
    const headers = calls[0][2]["headers"] as Record<string, string>;

    const expectedBody = JSON.stringify(SAMPLE_PAYLOAD);
    const expectedSig = `sha256=${createHmac("sha256", TEST_SECRET).update(expectedBody).digest("hex")}`;

    expect(headers["X-OpenCred-Signature"]).toBe(expectedSig);
    expect(headers["X-OpenCred-Event"]).toBe("batch.completed");
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers["User-Agent"]).toBe("OpenCred-Server");
    expect(calls[0][2]["method"]).toBe("POST");
    expect(calls[0][2]["body"]).toBe(expectedBody);
  });

  it("refuses delivery when secret is empty (LOW-04)", async () => {
    const calls = mockPinnedFetch(new Response("ok", { status: 200 }));

    // Empty secret is a programming error at this layer — the route-level
    // guard is responsible for rejecting webhookUrl+missing-secret requests
    // before calling `deliverWebhook`. See `POST /credentials/batch`.
    await expect(deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, "")).rejects.toThrow(
      /requires a non-empty secret/i,
    );

    // Crucially: no outbound request was made.
    expect(calls).toHaveLength(0);
  });

  it("retries on failure and succeeds on third attempt", async () => {
    const calls = mockPinnedFetch(
      new Error("network error"),
      new Response("error", { status: 500 }),
      new Response("ok", { status: 200 }),
    );

    await deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET);

    expect(calls).toHaveLength(3);
  });

  it("throws after all retries exhausted", async () => {
    mockPinnedFetch(
      new Response("error", { status: 500 }),
      new Response("error", { status: 502 }),
      new Response("error", { status: 503 }),
    );

    await expect(deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET)).rejects.toThrow(
      "Webhook returned HTTP 503",
    );
  });

  it("rejects non-HTTPS URLs", async () => {
    const calls = mockPinnedFetch();

    await expect(
      deliverWebhook("http://example.com/webhook", SAMPLE_PAYLOAD, TEST_SECRET),
    ).rejects.toThrow("Webhook URL must use HTTPS");

    expect(calls).toHaveLength(0);
  });

  it("rejects webhook URLs that resolve to private IPs", async () => {
    vi.mocked(dnsPromises.resolve).mockResolvedValue(["192.168.1.1"]);
    const calls = mockPinnedFetch();

    await expect(deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET)).rejects.toThrow(
      "Webhook URL resolves to private IP",
    );

    expect(calls).toHaveLength(0);
  });

  it("rejects webhook URLs that resolve to loopback IPs", async () => {
    vi.mocked(dnsPromises.resolve).mockResolvedValue(["127.0.0.1"]);
    const calls = mockPinnedFetch();

    await expect(deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET)).rejects.toThrow(
      "Webhook URL resolves to private IP",
    );

    expect(calls).toHaveLength(0);
  });

  it("rejects when ANY resolved address is private, even if the first is public", async () => {
    vi.mocked(dnsPromises.resolve).mockResolvedValue(["93.184.216.34", "169.254.169.254"]);
    const calls = mockPinnedFetch();

    await expect(deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET)).rejects.toThrow(
      "Webhook URL resolves to private IP",
    );

    expect(calls).toHaveLength(0);
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
    expect(keys).toEqual([
      "jobId",
      "status",
      "total",
      "successCount",
      "errorCount",
      "skippedCount",
    ]);

    // Must not contain anything that looks like credential content
    expect(serialized).not.toContain("credentialSubject");
    expect(serialized).not.toContain("proof");
    expect(serialized).not.toContain("verifiableCredential");
  });

  it("succeeds on first attempt with 2xx response", async () => {
    mockPinnedFetch(new Response("accepted", { status: 202 }));

    await expect(deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET)).resolves.toBeUndefined();
  });

  // ── DNS-rebinding (TOCTOU) protection ──────────────────────────────

  it("keeps the original hostname in the URL so TLS validates against it", async () => {
    const calls = mockPinnedFetch(new Response("ok", { status: 200 }));

    await deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET);

    expect(String(calls[0][0])).toBe(TEST_URL);
    // No `Host` override — that is what broke certificate validation before.
    const headers = calls[0][2]["headers"] as Record<string, string>;
    expect(headers["Host"]).toBeUndefined();
  });

  it("pins the connection to the validated addresses", async () => {
    vi.mocked(dnsPromises.resolve).mockResolvedValue(["93.184.216.34"]);
    const calls = mockPinnedFetch(new Response("ok", { status: 200 }));

    await deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET);

    expect(calls[0][1]).toEqual(["93.184.216.34"]);
  });

  it("pins the FULL resolved address set, not just the first (multi-A / dual-stack hosts)", async () => {
    const resolved = ["93.184.216.34", "93.184.216.35", "2606:2800:220:1:248:1893:25c8:1946"];
    vi.mocked(dnsPromises.resolve).mockResolvedValue(resolved);
    const calls = mockPinnedFetch(new Response("ok", { status: 200 }));

    await deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET);

    expect(calls[0][1]).toEqual(resolved);
  });

  it("preserves path and query in the pinned request URL", async () => {
    const calls = mockPinnedFetch(new Response("ok", { status: 200 }));

    await deliverWebhook("https://example.com/hooks/batch?token=abc", SAMPLE_PAYLOAD, TEST_SECRET);

    const requested = new URL(String(calls[0][0]));
    expect(requested.hostname).toBe("example.com");
    expect(requested.pathname).toBe("/hooks/batch");
    expect(requested.searchParams.get("token")).toBe("abc");
  });

  it("resolves DNS once and pins every retry to the SAME validated addresses (rebinding)", async () => {
    // A rebinding resolver: the first answer is public (passes validation),
    // every later answer is the cloud-metadata address. With the connection
    // pinned there is no second lookup for the attacker to poison.
    vi.mocked(dnsPromises.resolve)
      .mockResolvedValueOnce(["93.184.216.34"])
      .mockResolvedValue(["169.254.169.254"]);

    const calls = mockPinnedFetch(
      new Response("error", { status: 500 }),
      new Response("error", { status: 502 }),
      new Response("ok", { status: 200 }),
    );

    await deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, TEST_SECRET);

    // DNS was consulted exactly once, before validation.
    expect(vi.mocked(dnsPromises.resolve)).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(3);
    for (const call of calls) {
      expect(call[1]).toEqual(["93.184.216.34"]);
      expect(call[1]).not.toContain("169.254.169.254");
    }
  });

  // LOW-04: the signing secret is the dedicated webhook secret, not the API
  // key. A receiver holding only the API key must not be able to verify the
  // signature — this enforces the rotation-separation property.
  it("signature verifies against OPENCRED_WEBHOOK_SECRET but NOT against OPENCRED_API_KEY", async () => {
    const webhookSecret = "webhook-secret-with-enough-entropy-32chars";
    const apiKey = "api-key-that-should-NOT-sign-webhooks-32chars";
    const calls = mockPinnedFetch(new Response("ok", { status: 200 }));

    await deliverWebhook(TEST_URL, SAMPLE_PAYLOAD, webhookSecret);

    const headers = calls[0][2]["headers"] as Record<string, string>;
    const bodyString = JSON.stringify(SAMPLE_PAYLOAD);
    const expectedWithWebhookSecret = `sha256=${createHmac("sha256", webhookSecret)
      .update(bodyString)
      .digest("hex")}`;
    const withApiKey = `sha256=${createHmac("sha256", apiKey).update(bodyString).digest("hex")}`;

    expect(headers["X-OpenCred-Signature"]).toBe(expectedWithWebhookSecret);
    expect(headers["X-OpenCred-Signature"]).not.toBe(withApiKey);
  });
});
