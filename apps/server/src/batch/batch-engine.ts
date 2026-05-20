/**
 * Batch issuance engine for the server (no Electron dependencies).
 *
 * Processes valid CSV rows through the credential issuance pipeline:
 * validate → build → sign → track progress.
 *
 * SECURITY INVARIANTS:
 *  - The signing key stays in-process — never transmitted.
 *  - Key material is NEVER logged.
 */

import { randomUUID, createHash } from "node:crypto";
import { cpus } from "node:os";
import pMap from "p-map";
import { CredentialBuilder } from "@opencred/vc-core";
import type { VerifiableCredential } from "@opencred/vc-core";
import { getValidator } from "../validator-singleton.js";
import {
  prepareVcJwtProof,
  completeVcJwtProof,
  prepareProof,
  completeProof,
  prepareEdDsaProof,
  completeEdDsaProof,
  prepareSdJwtVcProof,
  completeSdJwtVcProof,
} from "@opencred/crypto";
import type { Signer } from "@opencred/signing";
import type { ParsedRow } from "./csv-parser.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type BatchRowStatus = "pending" | "processing" | "success" | "error" | "skipped";

export interface BatchRowResult {
  rowIndex: number;
  status: BatchRowStatus;
  error?: string;
  credential?: VerifiableCredential | string;
  isCompactToken?: boolean;
}

export interface BatchProgress {
  total: number;
  completed: number;
  successCount: number;
  errorCount: number;
  skippedCount: number;
  rows: BatchRowResult[];
  running: boolean;
  cancelled: boolean;
}

export type ProofFormat = "vc-jwt" | "data-integrity" | "sd-jwt-vc";

export interface BatchConfig {
  schemaId: string;
  issuerDid: string;
  validFrom: string;
  validUntil?: string;
  revocationRegistryUrl?: string;
  additionalTypes?: string[];
  proofFormat?: ProofFormat;
  selectiveDisclosureClaims?: string[];
  credentialSchemaUrl?: string;
}

/**
 * Resolve the worker-pool concurrency for the batch engine.
 *
 * Order of precedence:
 *  1. An explicit numeric override (used by tests). Any finite value is
 *     clamped to at least 1 — a `pLimit(0)` call would throw, and the
 *     intent of "override to 0" is operationally meaningless.
 *  2. `OPENCRED_BATCH_CONCURRENCY` env var, if it parses to a positive integer.
 *  3. `min(4, os.cpus().length)` — a sane default that keeps small servers
 *     from over-subscribing while still extracting useful parallelism on
 *     a typical 4+ core box.
 *
 * Exported so tests can assert the env-var path independently of the engine.
 */
export function resolveBatchConcurrency(override?: number): number {
  if (typeof override === "number" && Number.isFinite(override)) {
    return Math.max(1, Math.floor(override));
  }
  const raw = process.env.OPENCRED_BATCH_CONCURRENCY;
  if (raw !== undefined && raw !== "") {
    const parsed = Number.parseInt(raw, 10);
    if (Number.isFinite(parsed) && parsed >= 1) {
      return parsed;
    }
  }
  const cores = cpus().length || 1;
  return Math.max(1, Math.min(4, cores));
}

// The Validator is a single process-wide instance constructed during
// bootstrap (see apps/server/src/validator-singleton.ts). Do not cache a
// local Validator at module scope — see Anand's P1-01.

// ---------------------------------------------------------------------------
// Batch engine
// ---------------------------------------------------------------------------

export interface BatchEngineOptions {
  /**
   * Maximum number of rows processed in parallel. When omitted, the engine
   * reads `OPENCRED_BATCH_CONCURRENCY` (env) and falls back to
   * `min(4, os.cpus().length)`. See {@link resolveBatchConcurrency}.
   *
   * Per-row error semantics are unchanged regardless of concurrency: a
   * failed row still produces `status: "error"` and never aborts the batch.
   * Output is order-preserving — `progress.rows[i]` always corresponds to
   * `parsedRows[i]`.
   */
  concurrency?: number;
}

export function createBatchEngine(
  signer: Signer,
  parsedRows: ParsedRow[],
  config: BatchConfig,
  options: BatchEngineOptions = {},
) {
  const progress: BatchProgress = {
    total: parsedRows.length,
    completed: 0,
    successCount: 0,
    errorCount: 0,
    skippedCount: 0,
    rows: parsedRows.map((row) => ({
      rowIndex: row.rowIndex,
      status: row.valid ? ("pending" as const) : ("skipped" as const),
      error: row.valid ? undefined : row.errors.map((e) => `${e.field}: ${e.message}`).join("; "),
    })),
    running: false,
    cancelled: false,
  };

  progress.skippedCount = progress.rows.filter((r) => r.status === "skipped").length;
  progress.completed = progress.skippedCount;

  async function processRow(parsedRow: ParsedRow, rowResult: BatchRowResult): Promise<void> {
    rowResult.status = "processing";

    try {
      // Validate
      getValidator().validateOrThrow(
        config.schemaId,
        parsedRow.mappedSubject as Record<string, unknown>,
      );

      // Build
      const builder = new CredentialBuilder()
        .setIssuer(config.issuerDid)
        .setValidFrom(config.validFrom);

      builder.setCredentialSubject(parsedRow.mappedSubject as Record<string, unknown>);

      if (config.additionalTypes) {
        for (const type of config.additionalTypes) builder.addType(type);
      }
      if (config.validUntil) builder.setValidUntil(config.validUntil);
      if (config.revocationRegistryUrl) {
        const credentialUuid = randomUUID();
        builder.setId(`urn:uuid:${credentialUuid}`);
        const revocationHash = createHash("sha256").update(credentialUuid).digest("hex");
        const statusListCredential = config.revocationRegistryUrl;
        const lookupUrl = statusListCredential.replace("/dedi/query/", "/dedi/lookup/");
        builder.setCredentialStatus({
          id: `${lookupUrl}/${revocationHash}`,
          type: "dedi",
          statusPurpose: "revocation",
          statusListCredential,
        });
      }
      if (config.credentialSchemaUrl) {
        builder.setSchema({ id: config.credentialSchemaUrl, type: "JsonSchema" });
      }

      const unsigned = builder.build();
      const proofFormat = config.proofFormat ?? "vc-jwt";
      const vct = config.additionalTypes?.[0] ?? config.schemaId;

      // Sign
      switch (proofFormat) {
        case "vc-jwt": {
          const vcAsRecord = unsigned as unknown as Record<string, unknown>;
          const { signingInput } = prepareVcJwtProof(vcAsRecord, signer.algorithm, {
            verificationMethod: signer.id,
          });
          const dataToSign = new TextEncoder().encode(signingInput);
          const signatureBytes = await signer.sign(dataToSign);
          const jwt = completeVcJwtProof(signingInput, signatureBytes);
          rowResult.credential = {
            ...unsigned,
            proof: { type: "JsonWebSignature2020", jwt },
          } as unknown as VerifiableCredential;
          rowResult.isCompactToken = false;
          break;
        }
        case "data-integrity": {
          const proofOptions = { verificationMethod: signer.id, proofPurpose: "assertionMethod" };
          if (signer.algorithm === "Ed25519") {
            const { dataToSign, proofConfig } = await prepareEdDsaProof(unsigned, proofOptions);
            const signatureBytes = await signer.sign(dataToSign);
            rowResult.credential = completeEdDsaProof(unsigned, proofConfig, signatureBytes);
          } else {
            const { dataToSign, proofConfig } = await prepareProof(
              unsigned,
              proofOptions,
              signer.algorithm as "P-256" | "P-384",
            );
            const signatureBytes = await signer.sign(dataToSign);
            rowResult.credential = completeProof(unsigned, proofConfig, signatureBytes);
          }
          rowResult.isCompactToken = false;
          break;
        }
        case "sd-jwt-vc": {
          const sdJwtOptions = {
            selectiveDisclosureClaims: config.selectiveDisclosureClaims ?? [],
            vct,
            verificationMethod: signer.id,
          };
          const { signingInput, disclosures } = prepareSdJwtVcProof(
            unsigned,
            signer.algorithm,
            sdJwtOptions,
          );
          const dataToSign = new TextEncoder().encode(signingInput);
          const signatureBytes = await signer.sign(dataToSign);
          rowResult.credential = completeSdJwtVcProof(signingInput, signatureBytes, disclosures);
          rowResult.isCompactToken = true;
          break;
        }
      }

      rowResult.status = "success";
      progress.successCount++;
    } catch (err) {
      rowResult.status = "error";
      rowResult.error = err instanceof Error ? err.message : "Unknown signing error";
      progress.errorCount++;
    }

    progress.completed++;
  }

  const concurrency = resolveBatchConcurrency(options.concurrency);

  return {
    async start(): Promise<BatchProgress> {
      progress.running = true;
      progress.cancelled = false;

      // Streaming bounded-concurrency worker pool. `p-map` iterates the
      // input lazily, so at any moment the runtime holds AT MOST
      // `concurrency + 1` pending mapper promises — not one per row. For a
      // 1M-row CSV that is the difference between allocating ~1M wrapped
      // promises up front (memory-unbounded) and a small fixed slab.
      //
      // Ordering: `p-map` preserves input order in its result array (we
      // don't read it — every row's outcome is written into the
      // pre-allocated `progress.rows[i]` slot at the index we pass to the
      // mapper), and `progress.rows[i]` is keyed by `i` directly, so
      // output ordering is preserved regardless of completion order.
      //
      // Per-row error semantics: `processRow` swallows its own exception
      // and writes status="error" on the row, so the mapper never throws.
      // We still pass `stopOnError: false` defensively — a future change
      // that lets a row exception escape will then degrade to "skip the
      // failing row" rather than "abort the whole batch", matching the
      // documented contract.
      await pMap(
        parsedRows,
        async (parsedRow, i) => {
          const rowResult = progress.rows[i];

          // Parse-failed and already-skipped rows are accounted for in the
          // initial progress object — nothing to schedule.
          if (!parsedRow.valid || rowResult.status === "skipped") return;

          // Cancellation check inside the worker so already-queued rows
          // short-circuit cleanly. Matches the serial loop's behaviour:
          // unstarted work is marked "skipped" with "Batch cancelled".
          if (progress.cancelled) {
            rowResult.status = "skipped";
            rowResult.error = "Batch cancelled";
            progress.skippedCount++;
            progress.completed++;
            return;
          }
          await processRow(parsedRow, rowResult);
        },
        { concurrency, stopOnError: false },
      );

      progress.running = false;
      return { ...progress, rows: [...progress.rows] };
    },

    cancel(): void {
      progress.cancelled = true;
    },

    getProgress(): BatchProgress {
      return { ...progress, rows: [...progress.rows] };
    },
  };
}

export type BatchEngine = ReturnType<typeof createBatchEngine>;
