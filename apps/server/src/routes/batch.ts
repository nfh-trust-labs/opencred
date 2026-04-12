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

// In-memory job store (keyed by job ID)
const jobs = new Map<
  string,
  {
    engine: BatchEngine;
    progress: BatchProgress | null;
    createdAt: string;
    webhookUrl?: string;
  }
>();

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
  const job = {
    engine,
    progress: null as BatchProgress | null,
    createdAt: new Date().toISOString(),
    webhookUrl: parsed.webhookUrl,
  };
  jobs.set(jobId, job);

  batchJobsTotal.inc({ status: "started" });

  // Start processing in background
  void engine.start().then((finalProgress) => {
    job.progress = finalProgress;
    batchJobsTotal.inc({ status: finalProgress.cancelled ? "cancelled" : "completed" });

    // Deliver webhook notification on completion (best-effort)
    if (job.webhookUrl) {
      const webhookPayload: WebhookPayload = {
        jobId,
        status: finalProgress.cancelled ? "cancelled" : "completed",
        total: finalProgress.total,
        successCount: finalProgress.successCount,
        errorCount: finalProgress.errorCount,
        skippedCount: finalProgress.skippedCount,
      };
      const secret = config.OPENCRED_API_KEY ?? "";
      deliverWebhook(job.webhookUrl, webhookPayload, secret).catch((err) => {
        getLogger().warn({ jobId, webhookUrl: job.webhookUrl, err }, "Webhook delivery failed");
      });
    }
  }).catch(() => {
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

export { batch };
