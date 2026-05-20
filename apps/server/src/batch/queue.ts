/**
 * BullMQ queue wiring for batch + webhook dispatch (Tier 3 #8 of #446).
 *
 * Two queues live here:
 *
 *  - `BATCH_QUEUE_NAME` — payload is `BatchJob` (from `@opencred/shared`).
 *    Produced by `routes/batch.ts` when `OPENCRED_BATCH_DISPATCH=queue`,
 *    consumed by `apps/server/src/worker.ts`. The worker runs the
 *    `StreamingBatchEngine` against the rows in the message and pushes
 *    progress frames into the JobStore via the engine's `onProgress`
 *    hook (added in this PR).
 *
 *  - `WEBHOOK_QUEUE_NAME` — payload is `WebhookDeliveryJob`. Produced
 *    by the batch worker on job completion (when `webhookUrl` is set),
 *    consumed by the webhook worker in the same process. Retry/DLQ
 *    semantics are handled by BullMQ itself.
 *
 * ---------------------------------------------------------------------------
 * SECURITY (CLAUDE.md)
 * ---------------------------------------------------------------------------
 *
 *  - Queue payloads NEVER contain key material. The signing key is loaded
 *    independently inside the worker process from `OPENCRED_KEY_PATH` (or
 *    a Cloud HSM provider), matching the API process's key-loading code
 *    path. See `apps/server/src/worker.ts`.
 *  - Webhook secrets NEVER enter queue payloads. The worker reads
 *    `OPENCRED_WEBHOOK_SECRET` from its own env at delivery time.
 *  - Failed jobs land in BullMQ's `failed` set (the DLQ). The payload
 *    is retained there for operator inspection but is bounded by the
 *    `removeOnFail.age` setting (24 h default).
 *  - `OPENCRED_REDIS_URL` may carry credentials inline. This module
 *    NEVER logs the full URL — only host:port via `safeRedisInfo`.
 */

import type { Logger } from "pino";
import type {
  BatchJob,
  WebhookDeliveryJob,
} from "@opencred/shared";
import { BATCH_QUEUE_NAME, WEBHOOK_QUEUE_NAME } from "@opencred/shared";
import type { ServerConfig } from "../config.js";
import { safeRedisInfo } from "./job-store/factory.js";

// ---------------------------------------------------------------------------
// Minimal queue surfaces — abstracted so the tests don't need real Redis.
// ---------------------------------------------------------------------------
//
// We deliberately do NOT import bullmq's `Queue` type into the
// route-side caller; only the `enqueue`-shape we use is part of the
// public surface, and the implementation is wrapped behind a thin
// `Queueing` interface. The worker process imports bullmq directly
// (see `apps/server/src/worker.ts`) — the abstraction is for the
// producer side which runs inside the API hot path.

export interface BatchQueue {
  /**
   * Add a `BatchJob` to the queue. Retries are NOT configured here —
   * the API's job is to enqueue exactly once and return 202. The
   * worker drives retry semantics inside `Worker` config.
   *
   * The optional `removeOnCompleteAgeSec` mirrors the server's
   * `OPENCRED_SESSION_TTL`: completed jobs stay in Redis for that
   * long before BullMQ's housekeeper sweeps them. This prevents
   * indefinite accumulation of completed job records on a busy
   * deployment.
   */
  add(payload: BatchJob, opts?: { removeOnCompleteAgeSec?: number }): Promise<void>;

  /** Release the underlying BullMQ Queue + IORedis socket. Idempotent. */
  close(): Promise<void>;
}

export interface WebhookQueue {
  /**
   * Add a `WebhookDeliveryJob`. Retries with exponential backoff are
   * configured here (`5 attempts × 2s base`) — see the BullMQ docs.
   * Failed jobs land in the `failed` set for DLQ inspection.
   */
  add(payload: WebhookDeliveryJob): Promise<void>;

  /** Release the underlying BullMQ Queue + IORedis socket. Idempotent. */
  close(): Promise<void>;
}

interface QueueDeps {
  /**
   * Lazy bullmq Queue factory. Production wiring (`buildQueues` below)
   * uses `loadRealBullMq`; unit tests inject a stub that records `.add`
   * calls without touching Redis.
   */
  createQueue?: (
    name: string,
    redisUrl: string,
    tls: boolean,
    rejectUnauthorized: boolean,
  ) => BullMqQueueLike;
}

/**
 * Subset of BullMQ's `Queue` we depend on. Defined here so unit tests
 * can provide a fake without installing bullmq.
 */
export interface BullMqQueueLike {
  add(
    jobName: string,
    payload: unknown,
    opts?: Record<string, unknown>,
  ): Promise<unknown>;
  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Build the producer-side BullMQ queues used by the API process. Only
 * called when `OPENCRED_BATCH_DISPATCH=queue` — `inline` mode never
 * touches a queue.
 *
 * The returned object is owned by the API process; the worker process
 * (`apps/server/src/worker.ts`) creates its own queue handles to enqueue
 * webhook deliveries from the consumer side.
 */
export async function buildQueues(
  config: ServerConfig,
  logger: Logger,
  deps: QueueDeps = {},
): Promise<{ batch: BatchQueue; webhook: WebhookQueue }> {
  if (!config.OPENCRED_REDIS_URL) {
    // Defensive — loadConfig() rejects this case at startup.
    throw new Error(
      "buildQueues called without OPENCRED_REDIS_URL — config validation should have caught this earlier.",
    );
  }

  const tls = config.OPENCRED_REDIS_URL.startsWith("rediss://");
  const make =
    deps.createQueue ??
    (await loadRealBullMq(config.OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED));

  const batchQueue = make(BATCH_QUEUE_NAME, config.OPENCRED_REDIS_URL, tls, true);
  const webhookQueue = make(
    WEBHOOK_QUEUE_NAME,
    config.OPENCRED_REDIS_URL,
    tls,
    true,
  );

  logger.info(
    {
      host: safeRedisInfo(config.OPENCRED_REDIS_URL),
      tls,
      batchQueue: BATCH_QUEUE_NAME,
      webhookQueue: WEBHOOK_QUEUE_NAME,
    },
    "Batch dispatch: BullMQ queue",
  );

  return {
    batch: {
      async add(payload, opts) {
        const removeOnCompleteAgeSec =
          opts?.removeOnCompleteAgeSec ?? config.OPENCRED_SESSION_TTL;
        await batchQueue.add(BATCH_QUEUE_NAME, payload, {
          // Use the OpenCred-assigned jobId as BullMQ's job id so a
          // duplicate enqueue is a no-op rather than a parallel run.
          // BullMQ deduplicates by jobId within the same queue. This
          // matters if a retry of the POST somehow reuses jobId.
          jobId: payload.jobId,
          removeOnComplete: { age: removeOnCompleteAgeSec },
          // DLQ retention: keep failed jobs 24h for operator inspection.
          // Bounded retention prevents a misbehaving webhook target
          // from filling Redis with permanent failures.
          removeOnFail: { age: 24 * 60 * 60 },
        });
      },
      async close() {
        await batchQueue.close();
      },
    },
    webhook: {
      async add(payload) {
        await webhookQueue.add(WEBHOOK_QUEUE_NAME, payload, {
          attempts: 5,
          backoff: { type: "exponential", delay: 2000 },
          // 1h retention for completed (debug), 24h for failed (DLQ).
          removeOnComplete: { age: 3600 },
          removeOnFail: { age: 24 * 60 * 60 },
        });
      },
      async close() {
        await webhookQueue.close();
      },
    },
  };
}

/**
 * Lazy import of bullmq so unit tests that exercise inline-mode code
 * paths don't have to install the full BullMQ + ioredis stack just to
 * type-check this module. Production wiring goes through this path.
 */
async function loadRealBullMq(
  rejectUnauthorized: boolean,
): Promise<
  (
    name: string,
    redisUrl: string,
    tls: boolean,
    enforceJobId: boolean,
  ) => BullMqQueueLike
> {
  const { Queue } = await import("bullmq");
  const { Redis } = await import("ioredis");
  return (name, redisUrl, tls, _enforceJobId) => {
    const connectionOpts: Record<string, unknown> = {
      // BullMQ requires `maxRetriesPerRequest: null` on the connection
      // shared with workers to avoid spurious lock loss. The Queue side
      // also benefits from durable retries — explicitly opt in.
      maxRetriesPerRequest: null,
      enableReadyCheck: false,
      retryStrategy: (times: number) => Math.min(1000 * 2 ** times, 10_000),
    };
    if (tls) connectionOpts.tls = { rejectUnauthorized };
    const connection = new Redis(redisUrl, connectionOpts);
    connection.on("error", () => {
      // ioredis emits "error" on transient reconnects; the route layer
      // surfaces operational failures via the enqueue path.
    });
    return new Queue(name, { connection }) as unknown as BullMqQueueLike;
  };
}
