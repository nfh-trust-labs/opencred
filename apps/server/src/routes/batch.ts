/**
 * Batch credential issuance endpoints.
 *
 * POST /credentials/batch           — start a batch job from CSV
 * GET  /credentials/batch/:jobId    — get batch progress
 * GET  /credentials/batch/:jobId/results — get batch results
 *
 * ---------------------------------------------------------------------------
 * STATE MODEL (Tier 2 #5 of nfh-trust-labs/opencred#446)
 * ---------------------------------------------------------------------------
 *
 * Two layers of state:
 *
 *  1. The JobStore (memory or Redis) — JSON-serializable {@link JobRecord}
 *     entries, one per job. Shared visibility: when the server runs as
 *     multiple replicas behind a Redis-backed store, replica B can read
 *     and answer GET requests for jobs that replica A is running.
 *
 *  2. An in-process `localEngines` map — live {@link BatchEngine}
 *     instances bound to whichever replica accepted the POST. Engines
 *     are NOT serializable (they hold closures over signer instances and
 *     mutable progress state), so cross-replica work stealing is out of
 *     scope for this PR. Tier 3 #8 (BullMQ/SQS) addresses that.
 *
 * As the engine runs, it periodically syncs its progress snapshot back
 * to the JobStore. Reads from any replica return the most recent
 * snapshot — either the live engine state (own replica) or the stored
 * record (other replicas).
 *
 * ---------------------------------------------------------------------------
 * SECURITY
 * ---------------------------------------------------------------------------
 *
 *  - The signing key is loaded at startup. Key material is never logged
 *    or returned in responses (CLAUDE.md rule 1).
 *  - Job records carry credential drafts (PII). The JobStore TTL is
 *    bounded by `OPENCRED_SESSION_TTL` (default 4h) — Redis enforces
 *    this via `SET ... EX`; memory enforces it via lazy + recurring
 *    purge (CLAUDE.md rule 3).
 *  - Webhook URLs and Redis URLs are never logged in cleartext.
 */

import { Hono } from "hono";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { hostname } from "node:os";
import { ValidationError } from "@opencred/shared";
import type { BatchJob, BatchJobConfig, BatchJobRow } from "@opencred/shared";
import { requireSigner } from "../signing/key-manager.js";
import { getConfig } from "../config.js";
import {
  parseCsvStreaming,
  StreamingCsvLimitError,
  StreamingCsvRecordSizeError,
} from "../batch/csv-parser.js";
import type { Delimiter, ParsedRow } from "../batch/csv-parser.js";
import { createStreamingBatchEngine } from "../batch/batch-engine.js";
import type { StreamingBatchEngine, BatchProgress, ProofFormat } from "../batch/batch-engine.js";
import { deliverWebhook } from "../batch/webhook.js";
import type { WebhookPayload } from "../batch/webhook.js";
import { getLogger } from "../logger.js";
import { rejectKeyMaterial, customizationSchema } from "./credentials.js";
import { batchJobsTotal } from "../metrics.js";
import { parseJsonBody } from "../middleware/parse-json.js";
import { MemoryJobStore } from "../batch/job-store/memory.js";
import type { JobRecord, JobStatus, JobStore } from "../batch/job-store/types.js";
import type { BatchQueue } from "../batch/queue.js";

const batch = new Hono();

// ---------------------------------------------------------------------------
// JobStore wiring
// ---------------------------------------------------------------------------
//
// The store is injected at server bootstrap via `setJobStore`. Until then
// (i.e. in tests that exercise the route without going through `index.ts`)
// the module falls back to a freshly constructed `MemoryJobStore`.
//
// Note: #577's pre-merge base still carried a `BatchJobEntry` in-memory
// interface from before #575 introduced the JobStore. That interface is
// intentionally dropped here — JobStore is the canonical cross-replica
// state, the `localEngines` Map below holds the (non-serializable) engine
// handle on the owning replica.

let jobStore: JobStore = new MemoryJobStore();

/**
 * Inject the production-configured JobStore. Called once at server
 * startup from `index.ts`. Tests may call this directly to substitute a
 * mock without spinning up a Hono app.
 */
export function setJobStore(store: JobStore): void {
  jobStore = store;
}

/**
 * Resolve the current JobStore. Exposed for diagnostic/shutdown helpers
 * that need to access the store without going through a route handler.
 */
export function getJobStore(): JobStore {
  return jobStore;
}

// ---------------------------------------------------------------------------
// Batch queue wiring (Tier 3 #8 of #446)
// ---------------------------------------------------------------------------
//
// When `OPENCRED_BATCH_DISPATCH=queue` is configured at startup,
// `index.ts` builds a BullMQ-backed BatchQueue and injects it here via
// `setBatchQueue`. The POST handler then enqueues a `BatchJob` instead
// of running the engine in-process.
//
// Default (`inline` mode): the queue stays `null` and the POST handler
// retains today's behaviour bit-for-bit.

let batchQueue: BatchQueue | null = null;

/**
 * Inject the BullMQ-backed batch queue. Called by `index.ts` only when
 * `OPENCRED_BATCH_DISPATCH=queue`. Tests pass a stub for the queue
 * dispatch path; pass `null` to revert to inline mode.
 */
export function setBatchQueue(queue: BatchQueue | null): void {
  batchQueue = queue;
}

// In-process map of live engines. Keyed by jobId, populated only on the
// replica that accepted the POST. Engines are removed once they settle
// (success / cancellation / failure) or when shutdown finalizes the
// batch — see `finalizeAllRunningJobs` below.
const localEngines = new Map<string, StreamingBatchEngine>();

// Per-job heartbeat timers (Tier 2 #6 of nfh-trust-labs/opencred#446).
//
// While an engine is running, this replica writes `lastSeenAt` to the
// shared JobStore every `OPENCRED_HEARTBEAT_INTERVAL_SEC`. A remote
// observer reading the record from a different replica uses the
// freshness of that timestamp to detect a dead owning replica — see
// `findStaleRunningJobs` in `batch/job-store/types.ts`.
//
// We do NOT auto-transition a stale record here: cross-replica work
// stealing is the job of an external queue (Tier 3 #8 / #583). The
// heartbeat is a liveness *signal*, not a coordination primitive.
const heartbeatTimers = new Map<string, NodeJS.Timeout>();

/**
 * Build a diagnostic identifier for the running replica. Embedded in
 * `JobRecord.ownerReplica` so an operator looking at a Redis-stored
 * record can tell which replica is driving the work.
 *
 * NOTE: hostname can be unreliable in some container runtimes; use it
 * as a best-effort hint, not for correctness.
 */
const REPLICA_ID = `${hostname()}:${process.pid}`;

/**
 * Start the heartbeat loop for a running job. Writes the current time
 * to the record's `lastSeenAt` field every `intervalSeconds`. Idempotent
 * — calling twice with the same id replaces the prior timer.
 *
 * The timer is `.unref()`ed so it never holds the process open on its
 * own; graceful shutdown's `finalizeAllRunningJobs` is the canonical
 * stop signal.
 */
function startHeartbeat(jobId: string, intervalSeconds: number, ttlSeconds: number): void {
  // Replace any prior timer for the same id — defensive, the route
  // normally only schedules one heartbeat per job.
  stopHeartbeat(jobId);
  const intervalMs = intervalSeconds * 1000;
  const timer = setInterval(() => {
    const lastSeenAt = new Date().toISOString();
    jobStore
      .update(
        jobId,
        (current) => {
          // Defensive: if the record settled between ticks (the engine's
          // `.then`/`.catch` ran first), skip the write — we'd otherwise
          // re-touch the TTL on a finished record, which is harmless but
          // muddies the dashboard.
          if (
            current.status === "completed" ||
            current.status === "failed" ||
            current.status === "cancelled" ||
            current.status === "interrupted"
          ) {
            return null;
          }
          return { ...current, lastSeenAt };
        },
        ttlSeconds,
      )
      .catch((err) => {
        // Best-effort: a missed heartbeat is exactly what a stale-job
        // observer is supposed to detect. We log at debug so a misconfigured
        // Redis doesn't drown the logs, but the symptom is visible
        // downstream regardless.
        getLogger().debug({ jobId, err }, "Heartbeat write failed");
      });
  }, intervalMs);
  timer.unref?.();
  heartbeatTimers.set(jobId, timer);
}

/**
 * Stop the heartbeat loop for a job. Safe to call for an unknown id —
 * no-op in that case. Called when the engine settles or when shutdown
 * tears down in-flight work.
 */
function stopHeartbeat(jobId: string): void {
  const timer = heartbeatTimers.get(jobId);
  if (timer) {
    clearInterval(timer);
    heartbeatTimers.delete(jobId);
  }
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

const batchRequestSchema = z.object({
  csvContent: z.string(),
  schemaId: z.string(),
  issuerDid: z.string(),
  validFrom: z.string(),
  validUntil: z.string().optional(),
  proofFormat: z.enum(["vc-jwt", "data-integrity", "jws-2020", "sd-jwt-vc"]).default("vc-jwt"),
  additionalTypes: z.array(z.string()).optional(),
  revocationRegistryUrl: z.string().url().optional(),
  credentialSchemaUrl: z.string().url().optional(),
  selectiveDisclosureClaims: z.array(z.string()).optional(),
  columnMapping: z.record(z.string()).optional(),
  delimiter: z.enum([",", ";", "\t"]).optional(),
  webhookUrl: z
    .string()
    .url()
    .refine((u) => u.startsWith("https://"), { message: "Webhook URL must use HTTPS" })
    .optional(),
  customization: customizationSchema,
});

// ---------------------------------------------------------------------------
// Status derivation
// ---------------------------------------------------------------------------

/**
 * Derive the canonical PRD §5.4.2 status enum from the engine's progress.
 * Mirrors the inline logic that lived in the GET handler pre-refactor.
 */
function deriveStatus(progress: BatchProgress | null): JobStatus {
  if (!progress) return "queued";
  if (progress.cancelled) return "cancelled";
  if (progress.running) {
    return progress.completed === 0 ? "queued" : "running";
  }
  if (progress.errorCount > 0 && progress.successCount === 0) return "failed";
  return "completed";
}

// ---------------------------------------------------------------------------
// Start batch
// ---------------------------------------------------------------------------

batch.post("/credentials/batch", async (c) => {
  const body = await parseJsonBody(c);
  // SECURITY: reject any request that contains private key material before
  // we do any other work. CSV rows can carry per-field data that embeds a
  // PEM block — the scanner walks recursively so every string in every row
  // is checked once. See CLAUDE.md rule 1.
  rejectKeyMaterial(body);
  const parsed = batchRequestSchema.parse(body);
  const config = getConfig();

  // LOW-04: supplying a webhookUrl requires a dedicated, configured secret.
  // Kept as a strict check — there is no `?? ""` fallback to `OPENCRED_API_KEY`
  // and no silent unsigned-delivery path. If the operator wants unsigned
  // delivery in the future, that requires an explicit opt-in env var, not
  // a missing-config fallthrough.
  if (parsed.webhookUrl && !config.OPENCRED_WEBHOOK_SECRET) {
    return c.json(
      {
        error: {
          code: "WEBHOOK_SECRET_REQUIRED",
          message: "OPENCRED_WEBHOOK_SECRET must be configured when a webhookUrl is supplied",
        },
      },
      400,
    );
  }

  // In inline mode the route requires a loaded signer up-front (the engine
  // runs in this process). In queue mode the SIGNING happens inside the
  // worker process, so the API can accept the POST without a local signer.
  // Worker boot-time also validates its own signer, so the request is
  // never dispatched against a worker without a key.
  const dispatchMode = batchQueue ? "queue" : "inline";
  const signer = dispatchMode === "inline" ? requireSigner() : null;

  // Streaming CSV parser (issue #446 Tier 2 #7). Replaces the old
  // `parseCsv(string)` path that materialised THREE in-memory copies
  // of the input (raw string → `rawRows: string[][]` split on \n →
  // `parsedRows: ParsedRow[]`) before any signing started.
  //
  // Row-count cap is enforced fail-fast inside the parser via
  // `maxRows`. The old `split(/\r?\n/)` pre-check ran a second full
  // pass over the body just to count lines — the streaming version
  // throws on the (N+1)th row and the remainder is never read.
  //
  // Issue #580: the parser is now fed DIRECTLY to the engine via a
  // counting passthrough generator. No `parsedRows: ParsedRow[]`
  // array is materialised. Counters and a bounded `parseErrors`
  // buffer are updated as a side-effect of the streaming pass, so
  // the 202 response shape is preserved without buffering every row.
  // Peak resident memory is O(longest row + parseErrors_cap) instead
  // of O(N * row_size).
  const parser = parseCsvStreaming(parsed.csvContent, {
    schemaId: parsed.schemaId,
    columnMapping: parsed.columnMapping,
    delimiter: parsed.delimiter as Delimiter | undefined,
    maxRows: config.OPENCRED_BATCH_ROW_LIMIT,
    // Defense-in-depth alongside OPENCRED_MAX_BATCH_BODY_BYTES. The
    // body-limit middleware bounds the whole request; this cap bounds
    // a single in-flight record so a no-newline / unclosed-quote
    // attacker can't pin the body budget on one record (#578).
    maxRecordBytes: config.OPENCRED_BATCH_MAX_RECORD_BYTES,
  });

  // Header parsing happens up-front so we can return `headers` in the
  // 202 response and so a malformed body surfaces as a 4xx before we
  // kick off the background engine.
  let headers: string[];
  try {
    headers = (await parser.headers()).headers;
  } catch (err) {
    if (err instanceof StreamingCsvLimitError) {
      throw new ValidationError(`Batch exceeds maximum of ${err.limit} rows. Split your CSV.`);
    }
    if (err instanceof StreamingCsvRecordSizeError) {
      // SECURITY: surface only the configured cap, not the offending
      // record content or byte position. The buffer may carry PII.
      throw new ValidationError(
        `CSV record exceeds maximum size of ${err.limit} bytes. Split your CSV or check for an unterminated quoted field.`,
      );
    }
    throw err;
  }

  // Drain the parser into an array, ticking counters + bounded parseErrors
  // as we go. The full row array is needed for queue mode (BullMQ payload
  // must be JSON-serializable). Inline mode reuses the same materialized
  // rows via a lazy iterator below — the route doesn't keep a second copy.
  //
  // PII NOTE per CLAUDE.md: row content never enters logs/spans;
  // `parseErrors` carries `rowIndex` (an ordinal, not user data) and the
  // schema validator's structured error tuples (`field` / `message`) — same
  // shape as before. The 100-entry cap (from #580) ensures a malicious
  // caller can't blow up the 202 response body with 1M error entries.
  const PARSE_ERRORS_LIMIT = 100;
  const parsedRows: ParsedRow[] = [];
  let validCount = 0;
  let invalidCount = 0;
  const parseErrors: Array<{ rowIndex: number; errors: ParsedRow["errors"] }> = [];
  let parseErrorsTruncated = 0;
  try {
    for await (const row of parser.rows()) {
      if (row.valid) {
        validCount++;
      } else {
        invalidCount++;
        if (parseErrors.length < PARSE_ERRORS_LIMIT) {
          parseErrors.push({ rowIndex: row.rowIndex, errors: row.errors });
        } else {
          parseErrorsTruncated++;
        }
      }
      parsedRows.push(row);
    }
  } catch (err) {
    if (err instanceof StreamingCsvLimitError) {
      throw new ValidationError(`Batch exceeds maximum of ${err.limit} rows. Split your CSV.`);
    }
    if (err instanceof StreamingCsvRecordSizeError) {
      // SECURITY: never leak the buffered bytes or row index — both
      // can carry PII / credential subject data.
      throw new ValidationError(
        `CSV record exceeds maximum size of ${err.limit} bytes. Split your CSV or check for an unterminated quoted field.`,
      );
    }
    throw err;
  }

  const jobId = randomUUID();
  const createdAt = new Date().toISOString();
  const ttlSeconds = config.OPENCRED_SESSION_TTL;

  const batchJobConfig: BatchJobConfig = {
    schemaId: parsed.schemaId,
    issuerDid: parsed.issuerDid,
    validFrom: parsed.validFrom,
    validUntil: parsed.validUntil,
    revocationRegistryUrl: parsed.revocationRegistryUrl,
    additionalTypes: parsed.additionalTypes,
    proofFormat: parsed.proofFormat as ProofFormat,
    selectiveDisclosureClaims: parsed.selectiveDisclosureClaims,
    credentialSchemaUrl: parsed.credentialSchemaUrl,
  };

  const initialRecord: JobRecord = {
    jobId,
    status: "queued",
    progress: null,
    createdAt,
    webhookUrl: parsed.webhookUrl,
    ownerReplica: REPLICA_ID,
    // Seed `lastSeenAt` to `createdAt` so the record carries a valid
    // freshness anchor before the first heartbeat tick. An observer
    // looking at the record between the initial write and the first
    // heartbeat sees a timestamp that's at most one heartbeat interval
    // old — which is inside the stale-threshold window.
    lastSeenAt: createdAt,
  };

  await jobStore.set(jobId, initialRecord, ttlSeconds);
  batchJobsTotal.inc({ status: "started" });

  // ----- Queue mode --------------------------------------------------
  //
  // The route enqueues a `BatchJob` and immediately returns 202. The
  // worker pulls the job, runs the engine, and pushes progress frames
  // into the same JobStore via the engine's `onProgress` hook.
  if (batchQueue) {
    // Convert parsed rows to the wire-format. `claims` is intentionally
    // `mappedSubject` (NOT `rawValues`) — the worker uses it directly
    // as the credentialSubject.
    const wireRows: BatchJobRow[] = parsedRows.map((r) => ({
      rowIndex: r.rowIndex,
      valid: r.valid,
      errors: r.valid ? undefined : r.errors.map((e) => `${e.field}: ${e.message}`),
      claims: r.valid ? r.mappedSubject : undefined,
    }));
    const message: BatchJob = {
      jobId,
      config: batchJobConfig,
      rows: wireRows,
      webhookUrl: parsed.webhookUrl,
      enqueuedByReplica: REPLICA_ID,
      enqueuedAt: createdAt,
    };
    try {
      await batchQueue.add(message, { removeOnCompleteAgeSec: ttlSeconds });
    } catch (err) {
      // Enqueue failure: mark the job failed in the store so a GET
      // doesn't return a stuck `queued` record. The 500 surfaces to the
      // client so the operator can retry.
      getLogger().warn({ jobId, err }, "Failed to enqueue batch job");
      await jobStore
        .update(
          jobId,
          (current) => ({
            ...current,
            status: "failed",
            completedAt: new Date().toISOString(),
          }),
          ttlSeconds,
        )
        .catch(() => undefined);
      batchJobsTotal.inc({ status: "failed" });
      return c.json(
        {
          error: {
            code: "QUEUE_ENQUEUE_FAILED",
            message: "Failed to enqueue batch job; check server logs",
          },
        },
        503,
      );
    }

    // Use the bounded parseErrors collected during the parser drain. Cap is
    // PARSE_ERRORS_LIMIT (100) — if more parse errors occurred, the
    // `_truncated` sentinel reports the overflow count so clients know to
    // re-check via GET /v1/credentials/batch/:jobId/results.
    const responseParseErrors: Array<{ rowIndex: number; errors: ParsedRow["errors"] }> = [
      ...parseErrors,
    ];
    if (parseErrorsTruncated > 0) {
      responseParseErrors.push({
        rowIndex: -1,
        errors: [
          {
            field: "_truncated",
            message: `+${parseErrorsTruncated} more errors omitted (cap: ${PARSE_ERRORS_LIMIT})`,
          },
        ],
      });
    }

    return c.json(
      {
        jobId,
        status: "queued" as const,
        headers,
        validCount,
        invalidCount,
        totalCount: parsedRows.length,
        parseErrors: responseParseErrors.length > 0 ? responseParseErrors : undefined,
        webhookUrl: parsed.webhookUrl,
      },
      202,
    );
  }

  // ----- Inline mode (default, back-compat) --------------------------

  // Async-iterable adapter over the array. Yields rows on demand so
  // the engine's `p-map` pulls one row at a time at the worker pool's
  // rate. The engine itself doesn't care that the underlying input is
  // already materialised — same code path as a true byte-stream feed.
  async function* sourceRows(): AsyncIterable<ParsedRow> {
    for (const row of parsedRows) yield row;
  }

  // `signer` is non-null here because we only enter the inline branch
  // when batchQueue is null, and the top of the handler `requireSigner()`s
  // when dispatchMode is "inline". The non-null assertion documents that
  // invariant rather than re-running the check.
  const engine = createStreamingBatchEngine(signer!, batchJobConfig, {
    source: sourceRows(),
    // OTel attribute for per-row spans (#581 / #446 Tier 3 #10). The
    // jobId is an opaque UUID — CLAUDE.md security invariant: span
    // attributes carry only opaque identifiers, never user-provided
    // data.
    jobId,
  });

  // Inline mode keeps the live engine on this replica so we can answer
  // GETs from its `getProgress()` without a Redis round-trip.
  localEngines.set(jobId, engine);

  // Tier 2 #6: start the heartbeat loop. Owning replica refreshes
  // `lastSeenAt` every `OPENCRED_HEARTBEAT_INTERVAL_SEC` until the
  // engine settles or shutdown tears it down. Queue mode does NOT start
  // a heartbeat here — the worker process owns the heartbeat for jobs
  // it picks up off the queue.
  startHeartbeat(jobId, config.OPENCRED_HEARTBEAT_INTERVAL_SEC, ttlSeconds);

  // Background driver — engine.start() returns a Promise that settles
  // once every row has been processed. We don't await it for the 202
  // response (the route awaits `parseCompletion` instead — see below);
  // .then/.catch handle post-completion bookkeeping in the background.
  const enginePromise = engine.start();
  void enginePromise
    .then(async (finalProgress) => {
      const completedAt = new Date().toISOString();
      const finalStatus = deriveStatus(finalProgress);
      batchJobsTotal.inc({ status: finalProgress.cancelled ? "cancelled" : "completed" });

      await jobStore
        .update(
          jobId,
          (current) => ({
            ...current,
            progress: finalProgress,
            completedAt,
            status: finalStatus,
          }),
          ttlSeconds,
        )
        .catch((err) => {
          getLogger().warn(
            { jobId, err },
            "Failed to write final batch progress to JobStore — local engine state is still authoritative for this replica",
          );
        });

      // The engine has settled — drop it from the local map so the
      // garbage collector can reclaim it. Future GETs read from the
      // JobStore record only.
      localEngines.delete(jobId);
      stopHeartbeat(jobId);

      // Deliver webhook notification on completion (best-effort).
      // LOW-04: `webhookSecret` is guaranteed non-empty at this point because
      // the route returned 400 WEBHOOK_SECRET_REQUIRED earlier if
      // `webhookUrl` was set without a configured secret.
      if (parsed.webhookUrl) {
        const webhookPayload: WebhookPayload = {
          jobId,
          status: finalProgress.cancelled ? "cancelled" : "completed",
          total: finalProgress.total,
          successCount: finalProgress.successCount,
          errorCount: finalProgress.errorCount,
          skippedCount: finalProgress.skippedCount,
        };
        const webhookSecret = config.OPENCRED_WEBHOOK_SECRET;
        if (webhookSecret) {
          deliverWebhook(parsed.webhookUrl, webhookPayload, webhookSecret).catch((err) => {
            getLogger().warn(
              { jobId, webhookUrl: parsed.webhookUrl, err },
              "Webhook delivery failed",
            );
          });
        }
      }
    })
    .catch(async (err) => {
      // Even on engine failure, push status=failed so a replica reading
      // the record sees a settled state.
      const completedAt = new Date().toISOString();
      batchJobsTotal.inc({ status: "failed" });
      getLogger().warn({ jobId, err }, "Batch engine crashed");
      await jobStore
        .update(
          jobId,
          (current) => ({ ...current, completedAt, status: "failed" as const }),
          ttlSeconds,
        )
        .catch(() => {
          // best-effort — if the store is also down there's nothing more we can do.
        });
      localEngines.delete(jobId);
      stopHeartbeat(jobId);
    });

  // Bounded parseErrors surface: when truncated, append a sentinel marker
  // so callers can detect the cap was hit without exposing unbounded
  // payload bytes (CLAUDE.md rule 5). Same shape as the queue-mode branch
  // above so clients see consistent semantics across dispatch modes.
  const inlineResponseParseErrors: Array<{ rowIndex: number; errors: ParsedRow["errors"] }> = [
    ...parseErrors,
  ];
  if (parseErrorsTruncated > 0) {
    inlineResponseParseErrors.push({
      rowIndex: -1,
      errors: [
        {
          field: "_truncated",
          message: `+${parseErrorsTruncated} more errors omitted (cap: ${PARSE_ERRORS_LIMIT})`,
        },
      ],
    });
  }

  return c.json(
    {
      jobId,
      // PRD §5.4.2 canonical field: `status`. The POST response always
      // emits "queued" — the engine has been started in the background
      // (`void engine.start().then(...)`) but hasn't transitioned yet.
      status: "queued" as const,
      headers,
      validCount,
      invalidCount,
      totalCount: parsedRows.length,
      parseErrors: inlineResponseParseErrors.length > 0 ? inlineResponseParseErrors : undefined,
      webhookUrl: parsed.webhookUrl,
    },
    202,
  );
});

// ---------------------------------------------------------------------------
// Get batch progress
// ---------------------------------------------------------------------------

batch.get("/credentials/batch/:jobId", async (c) => {
  const jobId = c.req.param("jobId");

  // Local engine wins when present — it's the freshest view of progress.
  // Otherwise fall back to the JobStore (this is the cross-replica path).
  const localEngine = localEngines.get(jobId);
  if (localEngine) {
    const progress = localEngine.getProgress();
    const status = deriveStatus(progress);
    // Best-effort sync to the JobStore so a remote replica can see the
    // updated frame. Failing this write is non-fatal — the local engine
    // is still authoritative for this replica.
    const config = getConfig();
    await jobStore
      .update(jobId, (current) => ({ ...current, progress, status }), config.OPENCRED_SESSION_TTL)
      .catch(() => undefined);
    return c.json(buildProgressResponse(jobId, progress, status));
  }

  const record = await jobStore.get(jobId);
  if (!record) {
    return c.json({ error: { code: "NOT_FOUND", message: `Batch job not found: ${jobId}` } }, 404);
  }

  return c.json(buildProgressResponse(jobId, record.progress, record.status));
});

function buildProgressResponse(jobId: string, progress: BatchProgress | null, status: JobStatus) {
  if (!progress) {
    // Job exists in the store but the engine hasn't produced a frame yet.
    // Return a zero-progress snapshot so callers always see the same
    // response shape.
    return {
      jobId,
      status,
      total: 0,
      completed: 0,
      succeeded: 0,
      failed: 0,
      successCount: 0,
      errorCount: 0,
      skippedCount: 0,
      running: status === "queued" || status === "running",
      cancelled: status === "cancelled",
    };
  }
  return {
    jobId,
    status,
    total: progress.total,
    completed: progress.completed,
    // PRD §5.4.2 canonical names + legacy aliases.
    succeeded: progress.successCount,
    failed: progress.errorCount,
    successCount: progress.successCount,
    errorCount: progress.errorCount,
    skippedCount: progress.skippedCount,
    running: progress.running,
    cancelled: progress.cancelled,
  };
}

// ---------------------------------------------------------------------------
// Get batch results
// ---------------------------------------------------------------------------

batch.get("/credentials/batch/:jobId/results", async (c) => {
  const jobId = c.req.param("jobId");

  const localEngine = localEngines.get(jobId);
  let progress: BatchProgress | null;

  if (localEngine) {
    progress = localEngine.getProgress();
  } else {
    const record = await jobStore.get(jobId);
    if (!record) {
      return c.json(
        { error: { code: "NOT_FOUND", message: `Batch job not found: ${jobId}` } },
        404,
      );
    }
    progress = record.progress;
  }

  if (progress?.running) {
    return c.json(
      {
        error: { code: "JOB_RUNNING", message: "Batch is still running. Check progress first." },
      },
      409,
    );
  }

  const rows = progress?.rows ?? [];
  const results = rows.map((r) => ({
    rowIndex: r.rowIndex,
    status: r.status,
    error: r.error,
    credential: r.credential
      ? typeof r.credential === "string"
        ? r.credential
        : r.credential
      : undefined,
    isCompactToken: r.isCompactToken,
  }));

  return c.json({ jobId, results });
});

// ---------------------------------------------------------------------------
// Shutdown — finalize in-flight jobs
// ---------------------------------------------------------------------------
//
// When SIGTERM/SIGINT lands, every in-flight engine on this replica is
// effectively interrupted. We can't reliably wait for them to drain
// (especially on a fast Cloud Run shutdown grace period), but we CAN
// publish a final record marking them `"interrupted"`. A downstream
// retry pipeline or operator dashboard can use that signal to decide
// whether to re-submit the work.

export async function finalizeAllRunningJobs(): Promise<number> {
  let count = 0;
  const config = getConfig();
  const completedAt = new Date().toISOString();
  for (const [jobId, engine] of localEngines) {
    // Mark the engine cancelled so its current row loop stops scheduling
    // new rows. Rows already in flight will complete naturally (they
    // hold the only reference to their signer call), but we don't wait.
    engine.cancel();
    // Stop heartbeat first — once the record is "interrupted" we don't
    // want a stray heartbeat tick to write `lastSeenAt` and make a
    // dead replica look alive in the next observer window.
    stopHeartbeat(jobId);
    await jobStore
      .update(
        jobId,
        (current) => {
          // If the engine somehow already settled between the read and
          // here, keep its terminal status — don't downgrade
          // "completed" / "failed" back to "interrupted".
          if (
            current.status === "completed" ||
            current.status === "failed" ||
            current.status === "cancelled"
          ) {
            return current;
          }
          return { ...current, status: "interrupted" as const, completedAt };
        },
        config.OPENCRED_SESSION_TTL,
      )
      .catch(() => undefined);
    count += 1;
  }
  localEngines.clear();
  return count;
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/**
 * Reset all module-level state. Tests call this between cases so a
 * previous test's engines/store don't leak into the next.
 */
export function __resetBatchStateForTesting(): void {
  localEngines.clear();
  for (const timer of heartbeatTimers.values()) {
    clearInterval(timer);
  }
  heartbeatTimers.clear();
  jobStore = new MemoryJobStore();
  batchQueue = null;
}

/**
 * Expose the local-engine map size for diagnostic asserts in tests.
 */
export function __getLocalEngineCount(): number {
  return localEngines.size;
}

/**
 * Expose the heartbeat-timer map size for diagnostic asserts in tests.
 * Used to verify the heartbeat is torn down on settle and on shutdown.
 */
export function __getHeartbeatTimerCount(): number {
  return heartbeatTimers.size;
}

export { batch };
