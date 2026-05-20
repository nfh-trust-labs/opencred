/**
 * OpenCred Batch + Webhook Worker — standalone Node process.
 *
 * Consumes the BullMQ queues populated by the API process when
 * `OPENCRED_BATCH_DISPATCH=queue`. One worker runs both the batch
 * consumer AND the webhook consumer in the same process — they share
 * the same Redis connection and the same signing-key load path as
 * the API container, which means a single worker image deploys cleanly
 * alongside the API service (see `docker-compose.yml`'s `worker:`
 * stanza added in this PR).
 *
 * Run with:
 *   node dist/worker.js
 *
 * The worker is a peer of the API process — it does NOT serve HTTP.
 * The only inbound traffic is the BullMQ poll loop against Redis;
 * everything else (signing, JobStore writes, webhook delivery) uses
 * the same modules the API uses.
 *
 * ---------------------------------------------------------------------------
 * SECURITY (CLAUDE.md)
 * ---------------------------------------------------------------------------
 *
 *  - The worker loads the signing key from `OPENCRED_KEY_PATH` (or a
 *    Cloud HSM provider) at startup, IDENTICAL to the API process. The
 *    key NEVER travels through the queue. Queue payloads carry only
 *    public credential data + `issuerDid` (CLAUDE.md rule 1).
 *  - `OPENCRED_WEBHOOK_SECRET` is read from the worker's own env when
 *    delivering. If a webhook job arrives but the worker has no secret
 *    configured, the job fails into the DLQ with a clear error rather
 *    than silently dropping (CLAUDE.md rule 5).
 *  - Job progress is written to the SAME JobStore the API reads from,
 *    so a 4-hour TTL is enforced uniformly. Payloads do NOT leak into
 *    worker logs — only `{jobId, rowCount}` ever appears in pino calls.
 */

import type { Job } from "bullmq";
import type { ServerConfig } from "./config.js";
import { ConfigError, loadConfig } from "./config.js";
import { createLogger, getLogger } from "./logger.js";
import { loadSigningKey, getActiveSigner, setActiveSigner } from "./signing/key-manager.js";
import { createSignerFromConfig } from "./signing/cloud-hsm/factory.js";
import { createJobStore } from "./batch/job-store/factory.js";
import { createStreamingBatchEngine } from "./batch/batch-engine.js";
import type { BatchProgress, ProofFormat } from "./batch/batch-engine.js";
import { deliverWebhook } from "./batch/webhook.js";
import { safeRedisInfo } from "./batch/job-store/factory.js";
import { batchJobsTotal } from "./metrics.js";
import type { JobStore } from "./batch/job-store/types.js";
import {
  BATCH_QUEUE_NAME,
  WEBHOOK_QUEUE_NAME,
  type BatchJob,
  type WebhookDeliveryJob,
} from "@opencred/shared";
import type { ParsedRow } from "./batch/csv-parser.js";
import { cpus } from "node:os";
import {
  deriveWorkerStatus as deriveStatus,
  wireRowToParsedRow,
} from "./batch/worker-helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function resolveWorkerConcurrency(config: ServerConfig): number {
  if (config.OPENCRED_WORKER_CONCURRENCY) return config.OPENCRED_WORKER_CONCURRENCY;
  return Math.max(1, Math.min(4, cpus().length || 1));
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

let config: ServerConfig;
try {
  config = loadConfig();
} catch (err) {
  if (err instanceof ConfigError) {
    process.stderr.write(`\n[opencred-worker] FATAL: ${err.message}\n\n`);
  } else if (err instanceof Error) {
    process.stderr.write(`\n[opencred-worker] FATAL: ${err.message}\n\n`);
  } else {
    process.stderr.write(`\n[opencred-worker] FATAL: failed to load configuration\n\n`);
  }
  process.exit(1);
}

// The worker only makes sense when queue dispatch is enabled.
if (config.OPENCRED_BATCH_DISPATCH !== "queue") {
  process.stderr.write(
    "\n[opencred-worker] FATAL: OPENCRED_BATCH_DISPATCH must be set to 'queue' to run the worker.\n\n",
  );
  process.exit(1);
}
if (!config.OPENCRED_REDIS_URL) {
  // Defensive — loadConfig already rejects this case when DISPATCH=queue.
  process.stderr.write("\n[opencred-worker] FATAL: OPENCRED_REDIS_URL is required.\n\n");
  process.exit(1);
}

const logger = createLogger();
logger.info(
  {
    redis: safeRedisInfo(config.OPENCRED_REDIS_URL),
    workerConcurrency: resolveWorkerConcurrency(config),
    webhookConcurrency: config.OPENCRED_WEBHOOK_WORKER_CONCURRENCY,
  },
  "Starting OpenCred Worker",
);

// SECURITY: identical key-loading code path to the API process. The
// worker container is treated as the same trust boundary as the API
// container — both deserve the same signing-key handling. The key
// NEVER passes through the queue payload (CLAUDE.md rule 1).
const cloudSigner = await createSignerFromConfig();
if (cloudSigner) {
  setActiveSigner(cloudSigner);
} else {
  loadSigningKey();
}
const signer = getActiveSigner();
if (!signer) {
  process.stderr.write(
    "\n[opencred-worker] FATAL: No signing key loaded. Set OPENCRED_KEY_PATH or configure OPENCRED_KMS_PROVIDER.\n\n",
  );
  process.exit(1);
}
logger.info(
  { keyId: signer.id, fingerprint: signer.metadata.fingerprint, algorithm: signer.algorithm },
  "Signer ready (worker)",
);

const jobStore: JobStore = await createJobStore(config, logger);

// We need to bootstrap the schema engine and the DeDi singleton because
// the batch engine calls `getValidator()` on every row. The worker
// pulls in the same modules the API uses — keeping the boot order
// consistent reduces drift risk between API and worker.
//
// Schema engine bootstrap mirrors apps/server/src/index.ts.
const { createRegistryWithUpdates, Validator } = await import("@opencred/schema-engine");
const { setSchemaRegistry } = await import("./schema-registry-singleton.js");
const { setValidator } = await import("./validator-singleton.js");
const { homedir } = await import("node:os");
const { join } = await import("node:path");
const schemaRegistry = await createRegistryWithUpdates({
  manifestUrl: config.OPENCRED_SCHEMA_UPDATE_URL,
  cacheDir: config.OPENCRED_SCHEMA_CACHE_DIR ?? join(homedir(), ".opencred", "schemas"),
  timeoutMs: 10_000,
  logger,
});
setSchemaRegistry(schemaRegistry);
setValidator(new Validator(schemaRegistry));
logger.info({ count: schemaRegistry.listSchemas().length }, "Schema registry initialised (worker)");

// ---------------------------------------------------------------------------
// BullMQ workers
// ---------------------------------------------------------------------------

const { Worker, Queue } = await import("bullmq");
const { Redis } = await import("ioredis");

const tls = config.OPENCRED_REDIS_URL.startsWith("rediss://");

function buildRedis() {
  const opts: Record<string, unknown> = {
    // BullMQ Worker REQUIRES maxRetriesPerRequest: null on its connection.
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
    retryStrategy: (times: number) => Math.min(1000 * 2 ** times, 10_000),
  };
  if (tls) {
    opts.tls = { rejectUnauthorized: config.OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED };
  }
  const r = new Redis(config.OPENCRED_REDIS_URL!, opts);
  r.on("error", () => {
    // ioredis fires "error" on reconnects. BullMQ handles the recovery;
    // we mute the EventEmitter so Node doesn't treat it as unhandled.
  });
  return r;
}

// A small per-process `Queue` handle used by the batch worker to
// enqueue webhook jobs after a batch completes. Keeping this in the
// worker process keeps the webhook fan-out close to the work that
// produced it.
const webhookQueueOut = new Queue(WEBHOOK_QUEUE_NAME, { connection: buildRedis() });

// --- Batch worker ----------------------------------------------------------

const batchWorker = new Worker<BatchJob>(
  BATCH_QUEUE_NAME,
  async (job: Job<BatchJob>) => {
    const { jobId, config: jobConfig, rows, webhookUrl } = job.data;
    const log = getLogger();
    log.info(
      { jobId, rowCount: rows.length, proofFormat: jobConfig.proofFormat },
      "Worker received batch job",
    );

    // Convert wire rows → engine rows and drive the streaming engine.
    const parsedRows = rows.map(wireRowToParsedRow);
    async function* iter(): AsyncIterable<ParsedRow> {
      for (const r of parsedRows) yield r;
    }
    const engine = createStreamingBatchEngine(
      signer!,
      {
        schemaId: jobConfig.schemaId,
        issuerDid: jobConfig.issuerDid,
        validFrom: jobConfig.validFrom,
        validUntil: jobConfig.validUntil,
        revocationRegistryUrl: jobConfig.revocationRegistryUrl,
        additionalTypes: jobConfig.additionalTypes,
        proofFormat: jobConfig.proofFormat as ProofFormat | undefined,
        selectiveDisclosureClaims: jobConfig.selectiveDisclosureClaims,
        credentialSchemaUrl: jobConfig.credentialSchemaUrl,
      },
      { source: iter() },
    );

    // Cross-process progress sync. Each frame from the engine writes
    // through the same JobStore the API reads from — so any replica's
    // GET /credentials/batch/:jobId returns the up-to-date view.
    engine.onProgress(async (frame: BatchProgress) => {
      await jobStore
        .update(
          jobId,
          (current) => ({
            ...current,
            progress: frame,
            status: deriveStatus(frame),
          }),
          config.OPENCRED_SESSION_TTL,
        )
        .catch((err) => {
          // Progress writes are best-effort. The final frame is
          // pushed below regardless, so a transient Redis blip
          // doesn't silently corrupt the job's terminal state.
          log.warn({ jobId, err }, "Worker progress write failed");
        });
    });

    const finalProgress = await engine.start();
    const finalStatus = deriveStatus(finalProgress);
    batchJobsTotal.inc({ status: finalProgress.cancelled ? "cancelled" : finalStatus });

    await jobStore
      .update(
        jobId,
        (current) => ({
          ...current,
          progress: finalProgress,
          status: finalStatus,
          completedAt: new Date().toISOString(),
        }),
        config.OPENCRED_SESSION_TTL,
      )
      .catch((err) => {
        // The job IS done; only the store write failed. The BullMQ
        // job ack succeeds so the queue doesn't re-run it; the next
        // GET on this job will see whatever the last successful
        // write said, which is acceptable degradation.
        log.warn({ jobId, err }, "Final progress write to JobStore failed");
      });

    // Enqueue webhook delivery if requested. The worker NEVER signs
    // the webhook here — that happens in the webhook consumer with
    // the per-process OPENCRED_WEBHOOK_SECRET. See SECURITY at top.
    if (webhookUrl) {
      try {
        const wh: WebhookDeliveryJob = {
          jobId,
          webhookUrl,
          payload: {
            jobId,
            status: finalProgress.cancelled ? "cancelled" : "completed",
            total: finalProgress.total,
            successCount: finalProgress.successCount,
            errorCount: finalProgress.errorCount,
            skippedCount: finalProgress.skippedCount,
          },
        };
        await webhookQueueOut.add(WEBHOOK_QUEUE_NAME, wh, {
          attempts: 5,
          backoff: { type: "exponential", delay: 2000 },
          removeOnComplete: { age: 3600 },
          removeOnFail: { age: 24 * 60 * 60 },
        });
      } catch (err) {
        log.warn({ jobId, err }, "Failed to enqueue webhook job");
      }
    }
  },
  {
    connection: buildRedis(),
    concurrency: resolveWorkerConcurrency(config),
  },
);

batchWorker.on("failed", (job, err) => {
  // DLQ safety: log the jobId and error only. The payload (which can
  // include PII-bearing credential drafts) NEVER goes into pino. See
  // CLAUDE.md rule 2.
  getLogger().warn({ jobId: job?.data.jobId, error: err.message }, "Batch job failed");
});
batchWorker.on("error", (err) => {
  getLogger().warn({ err: err.message }, "Batch worker error");
});

// --- Webhook worker --------------------------------------------------------

// At-boot guard (CLAUDE.md rule 5): if a webhook job exists with no
// secret configured, fail it into the DLQ rather than dropping silently.
const webhookWorker = new Worker<WebhookDeliveryJob>(
  WEBHOOK_QUEUE_NAME,
  async (job: Job<WebhookDeliveryJob>) => {
    const { jobId, webhookUrl, payload } = job.data;
    const secret = config.OPENCRED_WEBHOOK_SECRET;
    if (!secret) {
      // Throw so BullMQ retries → DLQ. The configured retry policy
      // (5 attempts × exp backoff) gives the operator time to fix
      // the env var without losing the delivery permanently.
      throw new Error(
        "OPENCRED_WEBHOOK_SECRET is unset in the worker process; webhook delivery cannot be signed",
      );
    }
    await deliverWebhook(webhookUrl, payload, secret);
    getLogger().info({ jobId }, "Webhook delivered");
  },
  {
    connection: buildRedis(),
    concurrency: config.OPENCRED_WEBHOOK_WORKER_CONCURRENCY,
  },
);
webhookWorker.on("failed", (job, err) => {
  // SECURITY: do NOT log the webhookUrl in cleartext on failure — the
  // URL itself can leak deployment topology. Log only the jobId.
  getLogger().warn({ jobId: job?.data.jobId, error: err.message }, "Webhook delivery failed");
});
webhookWorker.on("error", (err) => {
  getLogger().warn({ err: err.message }, "Webhook worker error");
});

logger.info(
  { batchQueue: BATCH_QUEUE_NAME, webhookQueue: WEBHOOK_QUEUE_NAME },
  "OpenCred Worker ready",
);

// ---------------------------------------------------------------------------
// Graceful drain (CLAUDE.md rule 3 — session data ephemeral)
// ---------------------------------------------------------------------------
//
// On SIGTERM the worker stops fetching new jobs, lets the current job
// promise resolve, then closes the JobStore + queue handles. If the
// SIGTERM-to-SIGKILL grace period expires while a job is still
// processing, BullMQ's stalled-job detection re-enqueues it. The
// re-run is at-least-once (see spike § 8) — same semantics the inline
// path's `finalizeAllRunningJobs` already documents.

let shuttingDown = false;
async function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, "Worker shutting down");
  try {
    await batchWorker.close();
    await webhookWorker.close();
    await webhookQueueOut.close();
    await jobStore.close();
  } catch (err) {
    logger.warn({ err: (err as Error).message }, "Error during worker shutdown");
  }
  logger.info("Worker stopped");
  process.exit(0);
}
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));

// Export the workers so tests can introspect them. Production never
// imports from here.
export { batchWorker, webhookWorker, webhookQueueOut };
