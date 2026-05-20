/**
 * Tests for the producer-side BullMQ queue factory
 * (`apps/server/src/batch/queue.ts`, Tier 3 #8 of #446).
 *
 * Goals:
 *
 *  1. The factory honours the `createQueue` injection seam so unit
 *     tests don't have to install Redis.
 *  2. `BatchQueue.add` passes the OpenCred jobId as BullMQ's job id
 *     (dedup safety) and configures TTL-bounded retention via
 *     `removeOnComplete.age` / `removeOnFail.age`.
 *  3. `WebhookQueue.add` configures the spike-defined retry policy
 *     (5 attempts × 2s exponential backoff) so a tweak to that policy
 *     can't ship by accident.
 *  4. `close()` propagates to the underlying queue handles.
 *
 * We do NOT exercise Redis or BullMQ themselves — that's the worker
 * integration test's concern.
 */

import { describe, it, expect, vi } from "vitest";
import { buildQueues, type BullMqQueueLike } from "../queue.js";
import type { ServerConfig } from "../../config.js";
import type { BatchJob, WebhookDeliveryJob } from "@opencred/shared";
import { BATCH_QUEUE_NAME, WEBHOOK_QUEUE_NAME } from "@opencred/shared";

function makeConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    OPENCRED_REDIS_URL: "redis://localhost:6379",
    OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED: true,
    OPENCRED_SESSION_TTL: 14_400,
    OPENCRED_BATCH_DISPATCH: "queue",
    ...overrides,
  } as unknown as ServerConfig;
}

function makeLogger() {
  const calls: Array<{ obj: Record<string, unknown>; msg: string }> = [];
  return {
    logger: {
      info: (obj: Record<string, unknown>, msg: string) => calls.push({ obj, msg }),
      warn: () => undefined,
      error: () => undefined,
      debug: () => undefined,
      fatal: () => undefined,
      trace: () => undefined,
    } as unknown as Parameters<typeof buildQueues>[1],
    calls,
  };
}

function makeFakeQueue(): BullMqQueueLike & { addCalls: Array<{ name: string; payload: unknown; opts?: Record<string, unknown> }>; closed: boolean } {
  const addCalls: Array<{ name: string; payload: unknown; opts?: Record<string, unknown> }> = [];
  let closed = false;
  return {
    addCalls,
    get closed() {
      return closed;
    },
    async add(name, payload, opts) {
      addCalls.push({ name, payload, opts });
      return { id: "stub" };
    },
    async close() {
      closed = true;
    },
  } as BullMqQueueLike & {
    addCalls: typeof addCalls;
    closed: boolean;
  };
}

describe("buildQueues", () => {
  it("returns batch + webhook handles named after the canonical queue names", async () => {
    const { logger, calls } = makeLogger();
    const made: BullMqQueueLike[] = [];
    const config = makeConfig();
    const queues = await buildQueues(config, logger, {
      createQueue: (_name) => {
        const fake = makeFakeQueue();
        made.push(fake);
        return fake;
      },
    });
    expect(made).toHaveLength(2);
    expect(queues.batch).toBeDefined();
    expect(queues.webhook).toBeDefined();
    // The boot log MUST NOT include the redis URL in cleartext.
    const bootLog = calls.find((c) => c.msg === "Batch dispatch: BullMQ queue");
    expect(bootLog).toBeDefined();
    expect(JSON.stringify(bootLog!.obj)).not.toContain("redis://");
  });

  it("BatchQueue.add sets jobId, removeOnComplete TTL, and removeOnFail DLQ retention", async () => {
    const { logger } = makeLogger();
    const queues: BullMqQueueLike[] = [];
    const config = makeConfig({ OPENCRED_SESSION_TTL: 3600 });
    const { batch } = await buildQueues(config, logger, {
      createQueue: () => {
        const f = makeFakeQueue();
        queues.push(f);
        return f;
      },
    });

    const payload: BatchJob = {
      jobId: "test-job-123",
      config: {
        schemaId: "x",
        issuerDid: "did:key:zStub",
        validFrom: "2025-06-15T00:00:00Z",
      },
      rows: [],
      enqueuedAt: "2025-06-15T00:00:00Z",
    };
    await batch.add(payload);

    // First fake queue is the batch queue.
    const batchFake = queues[0] as unknown as ReturnType<typeof makeFakeQueue>;
    expect(batchFake.addCalls).toHaveLength(1);
    const { opts, name } = batchFake.addCalls[0];
    expect(name).toBe(BATCH_QUEUE_NAME);
    expect(opts?.jobId).toBe("test-job-123");
    expect((opts?.removeOnComplete as { age: number }).age).toBe(3600);
    // 24h DLQ retention is the documented contract.
    expect((opts?.removeOnFail as { age: number }).age).toBe(24 * 60 * 60);
  });

  it("WebhookQueue.add uses the spike-defined retry policy (5 attempts, 2s exp backoff)", async () => {
    const { logger } = makeLogger();
    const queues: BullMqQueueLike[] = [];
    const config = makeConfig();
    const { webhook } = await buildQueues(config, logger, {
      createQueue: () => {
        const f = makeFakeQueue();
        queues.push(f);
        return f;
      },
    });

    const payload: WebhookDeliveryJob = {
      jobId: "j1",
      webhookUrl: "https://hook.example.com/x",
      payload: {
        jobId: "j1",
        status: "completed",
        total: 0,
        successCount: 0,
        errorCount: 0,
        skippedCount: 0,
      },
    };
    await webhook.add(payload);

    // queues[1] is the webhook queue.
    const webhookFake = queues[1] as unknown as ReturnType<typeof makeFakeQueue>;
    expect(webhookFake.addCalls).toHaveLength(1);
    const { opts, name } = webhookFake.addCalls[0];
    expect(name).toBe(WEBHOOK_QUEUE_NAME);
    expect(opts?.attempts).toBe(5);
    expect((opts?.backoff as { type: string; delay: number }).type).toBe("exponential");
    expect((opts?.backoff as { type: string; delay: number }).delay).toBe(2000);
    // Completed jobs retained for 1 h, failed for 24 h.
    expect((opts?.removeOnComplete as { age: number }).age).toBe(3600);
    expect((opts?.removeOnFail as { age: number }).age).toBe(24 * 60 * 60);
  });

  it("close() propagates to both underlying queues", async () => {
    const { logger } = makeLogger();
    const queues: BullMqQueueLike[] = [];
    const { batch, webhook } = await buildQueues(makeConfig(), logger, {
      createQueue: () => {
        const f = makeFakeQueue();
        queues.push(f);
        return f;
      },
    });
    const closeSpy = vi.fn();
    queues[0].close = async () => {
      closeSpy("batch");
    };
    queues[1].close = async () => {
      closeSpy("webhook");
    };
    await batch.close();
    await webhook.close();
    expect(closeSpy).toHaveBeenCalledWith("batch");
    expect(closeSpy).toHaveBeenCalledWith("webhook");
  });
});
