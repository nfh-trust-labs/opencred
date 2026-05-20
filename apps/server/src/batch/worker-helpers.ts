/**
 * Pure helpers shared by `apps/server/src/worker.ts`.
 *
 * The worker entry point has a top-level bootstrap that loads
 * config + signing keys + Redis — it isn't directly importable from
 * a unit test without standing those up. The helpers below are pure
 * functions, so they live in their own module to keep the test
 * surface clean. The worker simply imports + re-uses them.
 */

import type { BatchJobRow } from "@opencred/shared";
import type { ParsedRow } from "./csv-parser.js";
import type { BatchProgress } from "./batch-engine.js";
import type { JobStatus } from "./job-store/types.js";

/**
 * Derive the canonical PRD §5.4.2 status from a progress frame.
 * Duplicates the route's `deriveStatus` so the worker doesn't need
 * to import from the route module (which pulls in Hono).
 */
export function deriveWorkerStatus(progress: BatchProgress | null): JobStatus {
  if (!progress) return "queued";
  if (progress.cancelled) return "cancelled";
  if (progress.running) return progress.completed === 0 ? "queued" : "running";
  if (progress.errorCount > 0 && progress.successCount === 0) return "failed";
  return "completed";
}

/**
 * Convert a wire-format `BatchJobRow` into the engine's `ParsedRow`
 * shape. The engine doesn't read `rawValues` during signing (it
 * builds the credential from `mappedSubject`), so we emit `{}` for
 * the field rather than serialising redundant copies in the queue
 * payload.
 *
 * Invalid rows preserve their original error array — the engine
 * threads them through to `progress.rows[].error` so consumers see
 * the same per-row diagnostic regardless of dispatch mode.
 */
export function wireRowToParsedRow(row: BatchJobRow): ParsedRow {
  if (row.valid) {
    return {
      rowIndex: row.rowIndex,
      rawValues: {},
      mappedSubject: (row.claims ?? {}) as Record<string, unknown>,
      valid: true,
      errors: [],
    };
  }
  return {
    rowIndex: row.rowIndex,
    rawValues: {},
    mappedSubject: {},
    valid: false,
    errors: (row.errors ?? []).map((e) => {
      const colon = e.indexOf(":");
      if (colon === -1) return { field: "row", message: e };
      return { field: e.slice(0, colon).trim(), message: e.slice(colon + 1).trim() };
    }),
  };
}
