/**
 * Batch credential issuance endpoints.
 *
 * POST /credentials/batch           — start a batch job from CSV
 * GET  /credentials/batch/:jobId    — get batch progress
 * GET  /credentials/batch/:jobId/results — get batch results
 *
 * SECURITY: The signing key is loaded at startup. Key material is never
 * logged or returned in responses.
 */

import { Hono } from "hono";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { ValidationError } from "@opencred/shared";
import { requireSigner } from "../signing/key-manager.js";
import { getConfig } from "../config.js";
import { parseCsv } from "../batch/csv-parser.js";
import type { Delimiter } from "../batch/csv-parser.js";
import { createBatchEngine } from "../batch/batch-engine.js";
import type { BatchEngine, BatchProgress, ProofFormat } from "../batch/batch-engine.js";
import { deliverWebhook } from "../batch/webhook.js";
import type { WebhookPayload } from "../batch/webhook.js";
import { getLogger } from "../logger.js";
import { rejectKeyMaterial, customizationSchema } from "./credentials.js";
import { batchJobsTotal } from "../metrics.js";

const batch = new Hono();

// In-memory job store (keyed by job ID).
//
// SECURITY: Per CLAUDE.md rule 3 ("Session data is ephemeral"), batch job
// entries — including their completed progress payloads — must be purged
// after `OPENCRED_SESSION_TTL`. See `startBatchJobCleanup` at the bottom
// of this module for the purge loop; `purgeExpiredBatchJobs` is the sync
// helper tests drive.
export interface BatchJobEntry {
  engine: BatchEngine;
  progress: BatchProgress | null;
  createdAt: string;
  /**
   * Set to an ISO-8601 timestamp the moment the engine's `start()` promise
   * settles (success, cancellation, or failure). The purge clock starts
   * ticking from `completedAt` when set; otherwise we fall back to
   * `createdAt` so that genuinely stuck jobs are still reclaimed.
   */
  completedAt?: string;
  webhookUrl?: string;
}

const jobs = new Map<string, BatchJobEntry>();

const batchRequestSchema = z.object({
  csvContent: z.string(),
  schemaId: z.string(),
  issuerDid: z.string(),
  validFrom: z.string(),
  validUntil: z.string().optional(),
  proofFormat: z.enum(["vc-jwt", "data-integrity", "sd-jwt-vc"]).default("vc-jwt"),
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

// --- Start batch ---

batch.post("/credentials/batch", async (c) => {
  const body = await c.req.json();
  // SECURITY: reject any request that contains private key material before
  // we do any other work. CSV rows can carry per-field data that embeds a
  // PEM block — the scanner walks recursively so every string in every row
  // is checked once. See CLAUDE.md rule 1.
  rejectKeyMaterial(body);
  const parsed = batchRequestSchema.parse(body);
  const signer = requireSigner();
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

  // Pre-check row count
  const lineCount = parsed.csvContent.split(/\r?\n/).filter((l) => l.trim().length > 0).length - 1;
  if (lineCount > config.OPENCRED_BATCH_ROW_LIMIT) {
    throw new ValidationError(
      `Batch exceeds maximum of ${config.OPENCRED_BATCH_ROW_LIMIT} rows (found ~${lineCount}). Split your CSV.`,
    );
  }

  const parseResult = parseCsv(parsed.csvContent, {
    schemaId: parsed.schemaId,
    columnMapping: parsed.columnMapping,
    delimiter: parsed.delimiter as Delimiter | undefined,
  });

  const engine = createBatchEngine(signer, parseResult.rows, {
    schemaId: parsed.schemaId,
    issuerDid: parsed.issuerDid,
    validFrom: parsed.validFrom,
    validUntil: parsed.validUntil,
    revocationRegistryUrl: parsed.revocationRegistryUrl,
    additionalTypes: parsed.additionalTypes,
    proofFormat: parsed.proofFormat as ProofFormat,
    selectiveDisclosureClaims: parsed.selectiveDisclosureClaims,
    credentialSchemaUrl: parsed.credentialSchemaUrl,
  });

  const jobId = randomUUID();
  const job: BatchJobEntry = {
    engine,
    progress: null,
    createdAt: new Date().toISOString(),
    webhookUrl: parsed.webhookUrl,
  };
  jobs.set(jobId, job);

  batchJobsTotal.inc({ status: "started" });

  // Start processing in background
  void engine
    .start()
    .then((finalProgress) => {
      job.progress = finalProgress;
      // TTL countdown starts once the engine is done. See `purgeExpiredBatchJobs`.
      job.completedAt = new Date().toISOString();
      batchJobsTotal.inc({ status: finalProgress.cancelled ? "cancelled" : "completed" });

      // Deliver webhook notification on completion (best-effort).
      // LOW-04: `webhookSecret` is guaranteed non-empty at this point because
      // the route returned 400 WEBHOOK_SECRET_REQUIRED earlier if
      // `webhookUrl` was set without a configured secret.
      if (job.webhookUrl) {
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
          deliverWebhook(job.webhookUrl, webhookPayload, webhookSecret).catch((err) => {
            getLogger().warn({ jobId, webhookUrl: job.webhookUrl, err }, "Webhook delivery failed");
          });
        }
      }
    })
    .catch(() => {
      // Even on engine failure, start the TTL clock so the entry gets purged.
      job.completedAt = new Date().toISOString();
      batchJobsTotal.inc({ status: "failed" });
    });

  const parseErrors = parseResult.rows
    .filter((r) => !r.valid)
    .map((r) => ({ rowIndex: r.rowIndex, errors: r.errors }));

  return c.json(
    {
      jobId,
      headers: parseResult.headers,
      validCount: parseResult.validCount,
      invalidCount: parseResult.invalidCount,
      totalCount: parseResult.totalCount,
      parseErrors: parseErrors.length > 0 ? parseErrors : undefined,
      webhookUrl: parsed.webhookUrl,
    },
    202,
  );
});

// --- Get batch progress ---

batch.get("/credentials/batch/:jobId", (c) => {
  const jobId = c.req.param("jobId");
  const job = jobs.get(jobId);

  if (!job) {
    return c.json({ error: { code: "NOT_FOUND", message: `Batch job not found: ${jobId}` } }, 404);
  }

  const progress = job.engine.getProgress();
  return c.json({
    jobId,
    total: progress.total,
    completed: progress.completed,
    successCount: progress.successCount,
    errorCount: progress.errorCount,
    skippedCount: progress.skippedCount,
    running: progress.running,
    cancelled: progress.cancelled,
  });
});

// --- Get batch results ---

batch.get("/credentials/batch/:jobId/results", (c) => {
  const jobId = c.req.param("jobId");
  const job = jobs.get(jobId);

  if (!job) {
    return c.json({ error: { code: "NOT_FOUND", message: `Batch job not found: ${jobId}` } }, 404);
  }

  const progress = job.engine.getProgress();

  if (progress.running) {
    return c.json(
      {
        error: { code: "JOB_RUNNING", message: "Batch is still running. Check progress first." },
      },
      409,
    );
  }

  const results = progress.rows.map((r) => ({
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
// TTL purge (HIGH-01)
// ---------------------------------------------------------------------------
//
// SECURITY: Per CLAUDE.md rule 3, session data — including the in-memory
// batch job registry — must not outlive `OPENCRED_SESSION_TTL`. Without a
// purge loop the map grows unboundedly and retains completed-credential
// metadata forever. `startBatchJobCleanup` is started once at server
// bootstrap (see `apps/server/src/index.ts`); tests drive the sync helper
// `purgeExpiredBatchJobs` directly so no real timers are needed.
//
// `GET /credentials/batch/:jobId` and `.../results` already return 404 when
// `jobs.get()` returns undefined, which is the correct post-purge behaviour.

/**
 * Synchronously evict every batch job whose (completed-or-created) timestamp
 * is older than `ttlMs` relative to `now`. Returns the number of evicted
 * jobs so callers can log meaningful metrics.
 *
 * A completed job's clock starts at `completedAt`; a still-running (or
 * orphaned) job falls back to `createdAt` so genuinely stuck jobs are still
 * reclaimed once the TTL elapses past their creation time.
 */
export function purgeExpiredBatchJobs(ttlMs: number, now: number): number {
  let deleted = 0;
  for (const [jobId, entry] of jobs) {
    const anchorIso = entry.completedAt ?? entry.createdAt;
    const anchor = Date.parse(anchorIso);
    if (!Number.isFinite(anchor)) continue;
    if (anchor + ttlMs < now) {
      jobs.delete(jobId);
      deleted += 1;
    }
  }
  return deleted;
}

/**
 * Start a recurring purge loop. Returns an unref'd `setInterval` handle so
 * the event loop is free to exit cleanly on shutdown. Kept exported so tests
 * and the server bootstrap can clear it via `clearInterval` if needed.
 */
export function startBatchJobCleanup(intervalMs: number, ttlMs: number): NodeJS.Timeout {
  const handle = setInterval(() => {
    const deleted = purgeExpiredBatchJobs(ttlMs, Date.now());
    if (deleted > 0) {
      getLogger().debug({ deleted }, "Purged expired batch jobs");
    }
  }, intervalMs);
  // Allow the process to exit even if this timer is still pending.
  handle.unref?.();
  return handle;
}

/**
 * Test-only helper — swaps the job store for a provided Map so unit tests
 * can seed fixed-shape entries without constructing a real BatchEngine.
 * Returns a restorer that resets the original.
 */
export function __setJobsForTesting(replacement: Map<string, BatchJobEntry>): () => void {
  const saved = new Map(jobs);
  jobs.clear();
  for (const [k, v] of replacement) jobs.set(k, v);
  return () => {
    jobs.clear();
    for (const [k, v] of saved) jobs.set(k, v);
  };
}

export { batch };
