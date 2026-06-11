/**
 * Compile-time contract test for BatchJob types (spike-1 / #446 Tier 3 #8).
 *
 * The types ship before any runtime consumer exists. This test exists so
 * the type contract is exercised by the test runner — a future refactor
 * that accidentally breaks the shape (renames a field, drops a literal)
 * fails CI rather than waiting for the impl PR to surface it.
 *
 * Asserts:
 *  - The queue-name constants are the exact literals documented in the
 *    spike (`opencred:batch`, `opencred:webhook`).
 *  - A representative `BatchJob` literal type-checks and round-trips
 *    through `JSON.stringify` / `JSON.parse` (the wire format).
 */

import { describe, expect, it } from "vitest";
import {
  BATCH_QUEUE_NAME,
  WEBHOOK_QUEUE_NAME,
  type BatchJob,
  type WebhookDeliveryJob,
} from "../batch-job.js";

describe("batch-job wire format", () => {
  it("uses the documented queue names", () => {
    expect(BATCH_QUEUE_NAME).toBe("opencred:batch");
    expect(WEBHOOK_QUEUE_NAME).toBe("opencred:webhook");
  });

  it("a representative BatchJob is JSON-round-trippable", () => {
    const job: BatchJob = {
      jobId: "11111111-2222-3333-4444-555555555555",
      enqueuedAt: "2026-05-20T00:00:00.000Z",
      enqueuedByReplica: "host-a:1234",
      webhookUrl: "https://example.test/webhook",
      config: {
        schemaId: "did:cord:c123/electricity-credential/v1",
        issuerDid: "did:web:issuer.example",
        validFrom: "2026-05-20T00:00:00.000Z",
        proofFormat: "vc-jwt",
      },
      rows: [
        { rowIndex: 0, valid: true, claims: { name: "Alice", id: "A-1" } },
        { rowIndex: 1, valid: false, errors: ["missing required: id"] },
      ],
    };
    const parsed = JSON.parse(JSON.stringify(job)) as BatchJob;
    expect(parsed.jobId).toBe(job.jobId);
    expect(parsed.rows).toHaveLength(2);
    expect(parsed.rows[0].claims).toEqual({ name: "Alice", id: "A-1" });
    expect(parsed.rows[1].valid).toBe(false);
  });

  it("a representative WebhookDeliveryJob is JSON-round-trippable", () => {
    const wh: WebhookDeliveryJob = {
      jobId: "11111111-2222-3333-4444-555555555555",
      webhookUrl: "https://example.test/webhook",
      payload: {
        jobId: "11111111-2222-3333-4444-555555555555",
        status: "completed",
        total: 100,
        successCount: 99,
        errorCount: 1,
        skippedCount: 0,
      },
    };
    const parsed = JSON.parse(JSON.stringify(wh)) as WebhookDeliveryJob;
    expect(parsed.payload.status).toBe("completed");
    expect(parsed.payload.total).toBe(100);
  });

  it("BatchJob.config.proofFormat accepts the three documented values", () => {
    // Compile-time check — if a value is dropped from the union, this fails to type-check.
    const formats: BatchJob["config"]["proofFormat"][] = [
      "vc-jwt",
      "data-integrity",
      "sd-jwt-vc",
      undefined,
    ];
    expect(formats).toHaveLength(4);
  });
});
