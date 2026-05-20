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
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import { getValidator } from "../validator-singleton.js";
import {
  prepareVcJwtProof,
  completeVcJwtProof,
  completeProof,
  completeEdDsaProof,
  prepareSdJwtVcProof,
  completeSdJwtVcProof,
  precomputeProofConfig,
  prepareProofWithPrecomputedConfig,
  type PrecomputedProofConfig,
} from "@opencred/crypto";
import type { Signer } from "@opencred/signing";
import { getCachedSignerDidDocument } from "@opencred/signing";
import type { ParsedRow } from "./csv-parser.js";
import { runInSpan } from "../observability/span-helpers.js";

/**
 * Warm the signer-DID-document cache for the batch's signer.
 *
 * The cache (see `packages/signing/src/signer-did-cache.ts`) is shared
 * process-wide and keyed on the signer's public-key fingerprint. By
 * resolving the document once at engine creation we ensure every row in
 * the batch (and every concurrent worker) sees a cache hit on subsequent
 * `getCachedSignerDidDocument(signer)` calls — no resolver work, no
 * allocation, just a Map lookup.
 *
 * Fire-and-forget: we don't await the warmup here because the engine
 * factory is synchronous. The first row that genuinely needs the
 * document will await the in-flight resolver call via the cache's
 * natural lookup flow.
 *
 * Best-effort: any error during resolution (did:web unsupported, mock
 * signer with a synthetic did:key, transient resolver failure) is
 * swallowed. The cache is a hot-path optimisation, not a correctness
 * gate — the signing path uses `signer.id` directly and the verifier
 * resolves the doc independently. We attach an empty `.catch` so a
 * rejected warmup promise doesn't surface as an unhandled rejection
 * and stay vitest's "unhandled error" reporter from firing in tests
 * that use stub signers (the warmup is best-effort, the test isn't
 * exercising it, so the rejection is noise).
 *
 * See #573 / #572.
 */
function warmSignerDidDocumentCache(signer: Signer): void {
  void getCachedSignerDidDocument(signer).catch(() => {
    /* best-effort warmup — swallow any error */
  });
}

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

  /**
   * Opaque batch identifier for OTel spans. When set, every per-row
   * span (`batch.row.process`) carries `batch.job_id` as an attribute
   * so operators can pivot from "this batch is slow" to "row 4137 is
   * the offender" in Tempo / Jaeger. Optional — when omitted the
   * attribute is simply not emitted.
   *
   * SECURITY: This MUST be the opaque jobId (UUID), never a credential
   * id, subject id, or any other user-derived identifier.
   */
  jobId?: string;
}

export function createBatchEngine(
  signer: Signer,
  parsedRows: ParsedRow[],
  config: BatchConfig,
  options: BatchEngineOptions = {},
) {
  // Pre-warm the signer-DID-document cache so every row's signing
  // operations see a hit. See {@link warmSignerDidDocumentCache}.
  warmSignerDidDocumentCache(signer);

  const jobIdForSpans = options.jobId;
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

  // Build an UnsignedCredential for the given row using the shared batch config.
  // Pure function over (row, config) — extracted so the proof-config
  // precomputation step (#571 — scale Tier 1 #4) can reuse it both for the
  // template (first row's @context) and per-row signing without duplication.
  function buildUnsignedForRow(parsedRow: ParsedRow): UnsignedCredential {
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
    return builder.build();
  }

  // Pre-computed proof-config bundle for data-integrity batches.
  //
  // The W3C ecdsa-rdfc-2019 / eddsa-rdfc-2022 signing input is
  //   hash(canonicalize(proofConfig)) || hash(canonicalize(document))
  // The first term is invariant across rows that share the same
  // `@context`, `verificationMethod`, `proofPurpose`, and `created`
  // timestamp. Every row in this batch shares those four fields, so we
  // canonicalize-and-hash the proof config exactly once, lazily on the
  // first row that needs it. Subsequent rows reuse the same hash bytes
  // (and the same `created` timestamp) which is the operational meaning
  // of "this batch was issued at time T" — see comments on
  // `precomputeProofConfig` in `@opencred/crypto`.
  //
  // Concurrency safety: with `OPENCRED_BATCH_CONCURRENCY > 1` multiple
  // rows enter `processRow` simultaneously, so a naive `if (cache ===
  // null)` guard would let several workers race past and each generate
  // its own bundle with its own `created` timestamp. We gate on the
  // promise reference itself: the first row that finds it `null`
  // installs the precompute promise, every other row awaits that same
  // promise. Result: exactly one bundle per batch, one timestamp, one
  // canonicalized proof-config hash — even on a 16-worker pool.
  //
  // For non-data-integrity proof formats this stays null; VC-JWT and
  // SD-JWT-VC don't perform JSON-LD canonicalization at all and would
  // gain nothing from the hoist.
  let precomputedProofConfigPromise: Promise<PrecomputedProofConfig> | null = null;

  async function processRow(parsedRow: ParsedRow, rowResult: BatchRowResult): Promise<void> {
    rowResult.status = "processing";

    // Span attributes are metadata-only — never the row payload.
    // CLAUDE.md: opaque ids only. `batch.row_index` is the CSV row
    // ordinal; `batch.job_id` (when supplied) is the opaque UUID the
    // batch route assigned. Neither carries credential subject data.
    const spanAttrs: Record<string, string | number> = {
      "batch.row_index": parsedRow.rowIndex,
      "batch.proof_format": config.proofFormat ?? "vc-jwt",
    };
    if (jobIdForSpans) spanAttrs["batch.job_id"] = jobIdForSpans;

    await runInSpan("batch.row.process", spanAttrs, async (span) => {
      try {
        // Validate
        getValidator().validateOrThrow(
          config.schemaId,
          parsedRow.mappedSubject as Record<string, unknown>,
        );

        const unsigned = buildUnsignedForRow(parsedRow);
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
            const proofOptions = {
              verificationMethod: signer.id,
              proofPurpose: "assertionMethod",
            };
            // Single-flight precompute. The first row to find the promise
            // slot `null` installs the precompute promise; every other row
            // (in concurrent execution) awaits the SAME promise. This is the
            // critical guard for `OPENCRED_BATCH_CONCURRENCY > 1`: without
            // it, the first `concurrency` rows each enter the if-branch and
            // generate independent bundles with independent `created`
            // timestamps, breaking the "one batch, one timestamp" invariant
            // and producing N times as much canonicalization work as we set
            // out to avoid.
            if (precomputedProofConfigPromise === null) {
              precomputedProofConfigPromise = precomputeProofConfig(
                unsigned,
                proofOptions,
                signer.algorithm,
              );
            }
            const precomputed = await precomputedProofConfigPromise;
            const { dataToSign, proofConfig } = await prepareProofWithPrecomputedConfig(
              unsigned,
              precomputed,
            );
            const signatureBytes = await signer.sign(dataToSign);
            if (signer.algorithm === "Ed25519") {
              rowResult.credential = completeEdDsaProof(unsigned, proofConfig, signatureBytes);
            } else {
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
      } finally {
        // The row status reflects business outcome (success / error /
        // skipped). We surface it as a span attribute so operators can
        // pivot from "this batch produced N errors" to "show me the
        // failing rows" in Tempo / Jaeger without re-reading the body.
        // Per-row exceptions are caught above (the engine never aborts
        // a batch on a single bad row) — so we mark span status from
        // the row status, not from a thrown exception.
        span.setAttribute("batch.row_status", rowResult.status);
      }
    });

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
      const runBatch = async () => {
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
      };

      // Wrap the whole batch run in a parent span so per-row spans
      // nest correctly. When tracing is disabled this collapses to a
      // single function call (no-op tracer).
      const batchAttrs: Record<string, string | number> = {
        "batch.proof_format": config.proofFormat ?? "vc-jwt",
        "batch.total_rows": parsedRows.length,
      };
      if (jobIdForSpans) batchAttrs["batch.job_id"] = jobIdForSpans;
      await runInSpan("batch.run", batchAttrs, runBatch);

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

// ---------------------------------------------------------------------------
// Streaming batch engine (issue #446 Tier 2 #7)
// ---------------------------------------------------------------------------

/**
 * Options for {@link createStreamingBatchEngine}. Mirrors
 * {@link BatchEngineOptions} but adds two streaming-specific knobs:
 *
 *   - `validateRow`   — injected schema validator. Same shape as the
 *                       buffered engine: returns `{ valid, errors }`. We
 *                       pass it explicitly so this engine does NOT pull
 *                       `validator-singleton` directly (keeps the engine
 *                       module testable without bootstrapping the
 *                       process-wide validator).
 *
 * Unlike the buffered engine the streaming variant does NOT know
 * `total` in advance — the row count is whatever the producer ends up
 * emitting. We update `progress.total` as rows arrive so the GET
 * `/credentials/batch/:jobId` endpoint converges on the true count as
 * the batch progresses.
 */
export interface StreamingBatchEngineOptions extends BatchEngineOptions {
  /**
   * Source of parsed rows. The engine pulls one row at a time through
   * `p-map`'s lazy iteration, so backpressure flows naturally: if every
   * worker slot is busy, the parser's `next()` call won't be invoked
   * and the upstream HTTP body stays unread on the socket. This is what
   * caps peak resident memory at `O(concurrency * row_size)`.
   */
  source: AsyncIterable<ParsedRow>;
}

/**
 * Build a streaming batch engine. Mirrors {@link createBatchEngine}'s
 * public surface — `start()` / `cancel()` / `getProgress()` — but
 * consumes rows from an async iterable instead of a pre-built array.
 *
 * Trade-offs vs. the buffered engine:
 *
 *   - `total` is unknown until iteration finishes. `progress.total`
 *     is incremented as rows arrive. The GET progress endpoint
 *     reports the running count, not a fixed estimate.
 *   - `progress.rows` grows on the fly. Order is still preserved:
 *     we record the `rowIndex` the parser assigned (which matches CSV
 *     input order), and `getProgress()` returns rows in iteration
 *     order (== input order, since `p-map` consumes the generator
 *     sequentially even when it dispatches work concurrently).
 *   - Skipped rows (parse-time validation failures) appear inline as
 *     they arrive, NOT pre-counted in the initial snapshot. This is a
 *     deliberate trade-off: pre-counting would require draining the
 *     stream first, which is what we're trying to avoid.
 */
export function createStreamingBatchEngine(
  signer: Signer,
  config: BatchConfig,
  options: StreamingBatchEngineOptions,
) {
  // Pre-warm the signer-DID-document cache. See the buffered engine for
  // rationale; same mechanism applies — every row's verificationMethod
  // is `signer.id`, so a single warmup serves the whole batch.
  warmSignerDidDocumentCache(signer);

  const jobIdForSpans = options.jobId;
  const progress: BatchProgress = {
    total: 0,
    completed: 0,
    successCount: 0,
    errorCount: 0,
    skippedCount: 0,
    rows: [],
    running: false,
    cancelled: false,
  };

  // Single-flight proof-config precompute (mirrors the buffered engine
  // from #572). Without this, every row independently re-canonicalizes
  // the proof-config JSON-LD — which is invariant across rows of the same
  // batch. The streaming path is now the production path, so it needs
  // the same hoist as the buffered engine to keep #572's 2.9× speedup.
  // eslint-disable-next-line prefer-const -- reassigned inside processRow closure
  let precomputedProofConfigPromise: Promise<PrecomputedProofConfig> | null = null;

  // Reuse the per-row processor by promoting it to a closure factory.
  // We do NOT call `createBatchEngine` here because that engine
  // pre-allocates a rows[] array sized to the input — exactly the
  // allocation we're trying to avoid.
  async function processRow(parsedRow: ParsedRow, rowResult: BatchRowResult): Promise<void> {
    rowResult.status = "processing";

    // Span attributes — opaque metadata only. See createBatchEngine
    // for the matching contract; we keep the same attribute names so
    // dashboards work uniformly across the buffered and streaming
    // engines.
    const spanAttrs: Record<string, string | number> = {
      "batch.row_index": parsedRow.rowIndex,
      "batch.proof_format": config.proofFormat ?? "vc-jwt",
    };
    if (jobIdForSpans) spanAttrs["batch.job_id"] = jobIdForSpans;

    await runInSpan("batch.row.process", spanAttrs, async (span) => {
      try {
        getValidator().validateOrThrow(
          config.schemaId,
          parsedRow.mappedSubject as Record<string, unknown>,
        );

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
            const proofOptions = {
              verificationMethod: signer.id,
              proofPurpose: "assertionMethod",
            };
            // Single-flight precompute — mirrors createBatchEngine. First row
            // installs the promise; concurrent rows await the SAME promise so
            // every row in the batch shares one canonicalized proof-config
            // and one `created` timestamp. See #572.
            if (precomputedProofConfigPromise === null) {
              precomputedProofConfigPromise = precomputeProofConfig(
                unsigned,
                proofOptions,
                signer.algorithm,
              );
            }
            const precomputed = await precomputedProofConfigPromise;
            const { dataToSign, proofConfig } = await prepareProofWithPrecomputedConfig(
              unsigned,
              precomputed,
            );
            const signatureBytes = await signer.sign(dataToSign);
            if (signer.algorithm === "Ed25519") {
              rowResult.credential = completeEdDsaProof(unsigned, proofConfig, signatureBytes);
            } else {
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
      } finally {
        span.setAttribute("batch.row_status", rowResult.status);
      }
    });

    progress.completed++;
  }

  const concurrency = resolveBatchConcurrency(options.concurrency);

  // The mapper bridges parsed rows → progress slots. The first thing it
  // does is register the row in `progress.rows` so a concurrent GET
  // progress request sees it; the actual work happens after.
  async function mapper(parsedRow: ParsedRow): Promise<void> {
    progress.total++;

    const rowResult: BatchRowResult = {
      rowIndex: parsedRow.rowIndex,
      status: parsedRow.valid ? "pending" : "skipped",
      error: parsedRow.valid
        ? undefined
        : parsedRow.errors.map((e) => `${e.field}: ${e.message}`).join("; "),
    };
    progress.rows.push(rowResult);

    if (!parsedRow.valid) {
      progress.skippedCount++;
      progress.completed++;
      return;
    }

    if (progress.cancelled) {
      rowResult.status = "skipped";
      rowResult.error = "Batch cancelled";
      progress.skippedCount++;
      progress.completed++;
      return;
    }

    await processRow(parsedRow, rowResult);
  }

  return {
    async start(): Promise<BatchProgress> {
      progress.running = true;
      progress.cancelled = false;

      // Parent span for the entire batch run; per-row spans nest under
      // this when tracing is enabled. Note `batch.total_rows` is set on
      // the parent at completion (we don't know it up front in the
      // streaming engine — that's the whole point of streaming).
      const batchAttrs: Record<string, string | number> = {
        "batch.proof_format": config.proofFormat ?? "vc-jwt",
      };
      if (jobIdForSpans) batchAttrs["batch.job_id"] = jobIdForSpans;

      try {
        await runInSpan("batch.run", batchAttrs, async (span) => {
          // `p-map` over an AsyncIterable: it pulls one item at a time
          // and never schedules more than `concurrency` mappers
          // in-flight. The producer (the streaming CSV parser) yields
          // rows lazily, so the upstream HTTP body is read at exactly
          // the rate the worker pool can drain it. This is the
          // backpressure path that bounds peak memory.
          await pMap(options.source, mapper, { concurrency, stopOnError: false });
          span.setAttribute("batch.total_rows", progress.total);
        });
      } catch (err) {
        // p-map can surface an upstream iterator error (e.g.
        // StreamingCsvLimitError thrown mid-stream). Mark the
        // batch failed but keep the rows we already processed.
        // The route promotes this into a 4xx; the engine just
        // records progress.
        progress.running = false;
        throw err;
      }

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

export type StreamingBatchEngine = ReturnType<typeof createStreamingBatchEngine>;
