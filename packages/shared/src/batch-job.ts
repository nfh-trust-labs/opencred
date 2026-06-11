/**
 * BatchJob — wire format for the external job queue (Tier 3 #8 of #446).
 *
 * This file ships as part of spike-1 (`docs/spikes/spike-1-external-job-queue.md`).
 * NOTHING in the server or worker imports it yet — it is the typed contract
 * that the follow-up implementation PR will use to enqueue work onto BullMQ.
 *
 * ---------------------------------------------------------------------------
 * WHY IS THIS HERE BEFORE THERE IS A QUEUE?
 * ---------------------------------------------------------------------------
 *
 * The spike doc commits to a specific message shape. Defining it as a pure
 * TypeScript interface — with no runtime dependency on BullMQ, ioredis, or
 * the server's `BatchEngine` — lets the impl PR import it into both the
 * producer (the API route) and the consumer (the worker entry point)
 * without circular or cross-package coupling. Putting it in `@opencred/shared`
 * keeps it available to any future workspace (e.g. a separate worker package).
 *
 * ---------------------------------------------------------------------------
 * SECURITY (CLAUDE.md)
 * ---------------------------------------------------------------------------
 *
 *  - This type is the queue payload. It MUST NEVER carry private key material
 *    (CLAUDE.md rule 1). The worker loads the signing key from its own
 *    environment (file path or Cloud HSM) — same code path as the API.
 *  - Webhook secrets are NEVER serialized into a BatchJob. The worker reads
 *    `OPENCRED_WEBHOOK_SECRET` from its own env when delivering.
 *  - The `rows` array contains parsed CSV data which is PII-bearing. Queue
 *    retention is bounded by `OPENCRED_SESSION_TTL` via BullMQ
 *    `removeOnComplete: { age }` / `removeOnFail: { age }` settings — same
 *    4 h default that governs the JobStore.
 *  - This module has ZERO runtime imports (no bundler entries, no side
 *    effects). Adding a runtime import here would pull queue infra into
 *    every consumer of `@opencred/shared` — bad. Keep it pure types.
 */

/**
 * Supported VC proof formats. Mirrors `ProofFormat` from
 * `apps/server/src/batch/batch-engine.ts` — duplicated here intentionally
 * to keep `@opencred/shared` free of server-internal dependencies.
 *
 * If this type ever drifts from the engine's `ProofFormat`, the impl PR
 * must surface a build break; consider re-exporting the engine type from
 * a neutral package in the future. For now keep the values in sync
 * manually — there are only three.
 */
export type BatchJobProofFormat = "vc-jwt" | "data-integrity" | "sd-jwt-vc";

/**
 * Per-row data as produced by the CSV parser. Mirrors the public shape
 * of `ParsedRow` from `apps/server/src/batch/csv-parser.ts`. Kept
 * minimal — the worker only needs the row index, the parsed claim
 * map, and the validity flag.
 */
export interface BatchJobRow {
  rowIndex: number;
  valid: boolean;
  /** Validation errors from the CSV parser. Present iff `valid: false`. */
  errors?: string[];
  /** Parsed claims, keyed by schema property name. Empty when `valid: false`. */
  claims?: Record<string, unknown>;
}

/**
 * The credential-shaping configuration for a batch. Mirrors `BatchConfig`
 * from the engine, minus any in-process-only fields. This is the
 * deterministic input to the engine — the same config + the same rows
 * + the same signer = the same output.
 */
export interface BatchJobConfig {
  schemaId: string;
  issuerDid: string;
  validFrom: string;
  validUntil?: string;
  proofFormat?: BatchJobProofFormat;
  additionalTypes?: string[];
  revocationRegistryUrl?: string;
  credentialSchemaUrl?: string;
  selectiveDisclosureClaims?: string[];
}

/**
 * Queue message payload for the `batch` queue.
 *
 * **Producer:** `apps/server/src/routes/batch.ts` — after parsing CSV and
 * writing the initial JobRecord, the route adds a `BatchJob` to the queue.
 *
 * **Consumer:** `apps/server/src/worker.ts` — pulls a BatchJob, runs the
 * `StreamingBatchEngine` with these rows + config, pushes progress frames
 * to the JobStore via the same `jobId`, and enqueues a webhook job on
 * completion if `webhookUrl` is set.
 *
 * **Why is `jobId` redundant with the BullMQ-assigned job id?**
 *
 * BullMQ assigns its own internal job id. We keep `jobId` here because
 * it's the public-facing identifier returned in the 202 response and
 * used as the JobStore key. Decoupling our id from BullMQ's id means
 * we can swap queue providers later without invalidating issued jobIds.
 */
export interface BatchJob {
  /** OpenCred-side job id (same as `JobRecord.jobId`). */
  jobId: string;
  /** Credential-shaping config; deterministic input to the engine. */
  config: BatchJobConfig;
  /** Parsed CSV rows. Valid + invalid rows are both included so the engine can mark invalid rows as `error` in the progress record. */
  rows: BatchJobRow[];
  /** Optional webhook destination. Worker enqueues a separate webhook job on completion. */
  webhookUrl?: string;
  /** Diagnostic identifier of the API replica that enqueued this job. */
  enqueuedByReplica?: string;
  /** ISO-8601 timestamp of enqueue. Used for queue-latency metrics. */
  enqueuedAt: string;
}

/**
 * Queue message payload for the `webhook` queue.
 *
 * **Producer:** the batch worker, on job completion.
 *
 * **Consumer:** `apps/server/src/webhook-worker.ts` — calls `deliverWebhook`
 * with the URL and payload. The webhook signing secret is NEVER part of
 * the payload — the worker reads `OPENCRED_WEBHOOK_SECRET` from its own
 * env. If the secret is unset, the worker fails the job into the DLQ
 * rather than silently dropping it.
 */
export interface WebhookDeliveryJob {
  jobId: string;
  webhookUrl: string;
  payload: {
    jobId: string;
    status: "completed" | "cancelled";
    total: number;
    successCount: number;
    errorCount: number;
    skippedCount: number;
  };
}

/**
 * Canonical queue names. Defined here so producer and consumer use the
 * same string literal — a typo would silently fork the wire protocol.
 */
export const BATCH_QUEUE_NAME = "opencred:batch" as const;
export const WEBHOOK_QUEUE_NAME = "opencred:webhook" as const;
