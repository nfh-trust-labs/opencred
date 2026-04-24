/**
 * Batch issuance engine for offline credential issuance.
 *
 * Processes all valid rows from a parsed CSV through the local signing flow,
 * signs each VC with the issuer's software key, packages each VC, and tracks
 * progress per row.
 *
 * Works entirely offline -- no network requests.
 *
 * SECURITY INVARIANTS:
 *  - The private key never leaves the issuer's machine.
 *  - Key material is NEVER logged -- only key IDs and fingerprints.
 *  - No network requests are made during batch processing.
 */

import { buildAndSign } from "../signing/local-signing-flow.js";
import type { LocalSigningOptions } from "../signing/local-signing-flow.js";
import { packageCredential } from "../packaging/packager.js";
import type { PackageFormat, PackagingResult } from "../packaging/packager.js";
import { queueRevocation } from "../main/revocation-queue.js";
import { extractRevocationHashFromStatusId } from "@opencred/crypto";
import type { Signer } from "../signing/types.js";
import type { VerifiableCredential } from "@opencred/vc-core";
import type { UiProofFormat } from "../shared/ipc-types.js";
import type { ParsedRow } from "./csv-parser.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Status of a single row in the batch. */
export type BatchRowStatus = "pending" | "processing" | "success" | "error" | "skipped";

/** Result for a single row in the batch. */
export interface BatchRowResult {
  /** The row index from the CSV. */
  rowIndex: number;
  /** Current processing status. */
  status: BatchRowStatus;
  /** Error message if status is 'error'. */
  error?: string;
  /** The signed credential (if status is 'success'). String for SD-JWT-VC compact tokens. */
  credential?: VerifiableCredential | string;
  /** Packaged outputs (if packaging was requested and succeeded). */
  packagingResult?: PackagingResult;
  /** Whether the credential is a compact token (SD-JWT-VC). */
  isCompactToken?: boolean;
}

/** Overall batch progress. */
export interface BatchProgress {
  /** Total number of rows to process. */
  total: number;
  /** Number of rows completed (success + error + skipped). */
  completed: number;
  /** Number of successful rows. */
  successCount: number;
  /** Number of error rows. */
  errorCount: number;
  /** Number of skipped rows (invalid at parse time). */
  skippedCount: number;
  /** Per-row results. */
  rows: BatchRowResult[];
  /** Whether the batch is currently running. */
  running: boolean;
  /** Whether the batch was cancelled. */
  cancelled: boolean;
}

/** Configuration for a batch issuance run. */
export interface BatchConfig {
  /** The schema ID for all credentials. */
  schemaId: string;
  /** The issuer DID. */
  issuerDid: string;
  /** ISO 8601 validFrom date. */
  validFrom: string;
  /** ISO 8601 validUntil date (optional). */
  validUntil?: string;
  /** Revocation registry URL (optional). */
  revocationRegistryUrl?: string;
  /** Additional credential types (optional). */
  additionalTypes?: string[];
  /** Output packaging formats. Defaults to ["json"]. */
  packageFormats?: PackageFormat[];
  /** Proof format (default: "vc-jwt"). */
  proofFormat?: UiProofFormat;
  /** Field names for SD-JWT-VC selective disclosure. */
  selectiveDisclosureClaims?: string[];
  /** Optional credential schema URL. */
  credentialSchemaUrl?: string;
}

// ---------------------------------------------------------------------------
// Batch engine
// ---------------------------------------------------------------------------

/**
 * Create a batch engine instance that processes parsed CSV rows.
 *
 * The engine maintains progress state and supports cancellation.
 * It processes rows sequentially to avoid overwhelming the signing pipeline
 * and to provide accurate progress tracking.
 *
 * @param signer - The Signer instance to use for all credentials.
 * @param parsedRows - The rows from CsvParseResult (all rows, including invalid ones).
 * @param config - Batch configuration (issuer DID, schema, etc.).
 * @returns An object with start(), cancel(), and getProgress() methods.
 */
export function createBatchEngine(signer: Signer, parsedRows: ParsedRow[], config: BatchConfig) {
  const packageFormats = config.packageFormats ?? ["json"];

  // Initialize progress
  const progress: BatchProgress = {
    total: parsedRows.length,
    completed: 0,
    successCount: 0,
    errorCount: 0,
    skippedCount: 0,
    rows: parsedRows.map((row) => ({
      rowIndex: row.rowIndex,
      status: row.valid ? "pending" : "skipped",
      error: row.valid ? undefined : row.errors.map((e) => `${e.field}: ${e.message}`).join("; "),
    })),
    running: false,
    cancelled: false,
  };

  // Count initially skipped rows
  progress.skippedCount = progress.rows.filter((r) => r.status === "skipped").length;
  progress.completed = progress.skippedCount;

  /** Optional callback invoked on each progress update. */
  let onProgress: ((p: BatchProgress) => void) | undefined;

  function notifyProgress(): void {
    onProgress?.({ ...progress, rows: [...progress.rows] });
  }

  /**
   * Process a single valid row.
   */
  async function processRow(parsedRow: ParsedRow, rowResult: BatchRowResult): Promise<void> {
    rowResult.status = "processing";
    notifyProgress();

    try {
      const signingOptions: LocalSigningOptions = {
        schemaId: config.schemaId,
        issuerDid: config.issuerDid,
        credentialSubject: parsedRow.mappedSubject as Record<string, unknown>,
        validFrom: config.validFrom,
        validUntil: config.validUntil,
        revocationRegistryUrl: config.revocationRegistryUrl,
        additionalTypes: config.additionalTypes,
        proofFormat: config.proofFormat,
        selectiveDisclosureClaims: config.selectiveDisclosureClaims,
        credentialSchemaUrl: config.credentialSchemaUrl,
      };

      // Build and sign the credential
      const result = await buildAndSign(signer, signingOptions);
      rowResult.credential = result.credential;
      rowResult.isCompactToken = result.isCompactToken;

      // Package the credential (only for JSON-based outputs, not compact tokens)
      if (!result.isCompactToken && packageFormats.length > 0) {
        rowResult.packagingResult = await packageCredential(
          result.credential as VerifiableCredential,
          packageFormats,
        );
      }

      // Queue revocation hash if a revocation registry URL is configured.
      //
      // The hash we queue MUST match what the verifier extracts from the
      // credential's `credentialStatus.id`. Otherwise the DeDi record we
      // publish is keyed by one hash while the verifier queries by another
      // and revocation is silently broken (see
      // `resolveRevocationHash` in `@opencred/crypto`).
      const credentialId = typeof result.credential === "string" ? undefined : result.credential.id;
      if (config.revocationRegistryUrl && credentialId) {
        const revocationHash = extractRevocationHashFromStatusId(result.credential);
        if (revocationHash) {
          queueRevocation(credentialId, config.revocationRegistryUrl, { revocationHash });
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
    notifyProgress();
  }

  return {
    /**
     * Start batch processing.
     *
     * Processes all valid rows sequentially. Invalid rows are automatically
     * skipped. The batch can be cancelled at any time via cancel().
     */
    async start(): Promise<BatchProgress> {
      progress.running = true;
      progress.cancelled = false;
      notifyProgress();

      for (let i = 0; i < parsedRows.length; i++) {
        // Check for cancellation
        if (progress.cancelled) {
          // Mark remaining pending rows as skipped
          for (let j = i; j < parsedRows.length; j++) {
            const rowResult = progress.rows[j];
            if (rowResult.status === "pending") {
              rowResult.status = "skipped";
              rowResult.error = "Batch cancelled";
              progress.skippedCount++;
              progress.completed++;
            }
          }
          break;
        }

        const parsedRow = parsedRows[i];
        const rowResult = progress.rows[i];

        // Skip invalid rows
        if (!parsedRow.valid || rowResult.status === "skipped") {
          continue;
        }

        await processRow(parsedRow, rowResult);
      }

      progress.running = false;
      notifyProgress();

      return { ...progress, rows: [...progress.rows] };
    },

    /**
     * Cancel the running batch.
     *
     * The current row will complete, but no further rows will be processed.
     */
    cancel(): void {
      progress.cancelled = true;
    },

    /**
     * Get the current batch progress.
     */
    getProgress(): BatchProgress {
      return { ...progress, rows: [...progress.rows] };
    },

    /**
     * Set the progress callback.
     */
    onProgressUpdate(callback: (p: BatchProgress) => void): void {
      onProgress = callback;
    },
  };
}

/** Return type of createBatchEngine. */
export type BatchEngine = ReturnType<typeof createBatchEngine>;
