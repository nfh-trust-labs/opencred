/**
 * CSV parser for batch credential issuance (server version).
 *
 * Thin wrapper over `@opencred/batch-core` that injects the server's
 * schema validator. The parsing logic itself (delimiter detection,
 * line parsing, column mapping, applyMapping Set hoist from P2-01)
 * now lives in batch-core — see Anand's P2-02.
 *
 * SECURITY: No key material is ever involved in parsing.
 */

import type { ValidationResult } from "@opencred/schema-engine";
import {
  applyMapping as applyMappingCore,
  detectDelimiter as detectDelimiterCore,
  parseCsv as parseCsvCore,
  parseRawCsv as parseRawCsvCore,
  streamingParseCsv as streamingParseCsvCore,
  StreamingCsvLimitError as StreamingCsvLimitErrorCore,
  type ColumnMapping as CoreColumnMapping,
  type CsvParseOptions as CoreCsvParseOptions,
  type CsvParseResult as CoreCsvParseResult,
  type Delimiter as CoreDelimiter,
  type ParsedRow as CoreParsedRow,
  type StreamingCsvInput as CoreStreamingCsvInput,
  type StreamingCsvOptions as CoreStreamingCsvOptions,
  type StreamingCsvParser as CoreStreamingCsvParser,
} from "@opencred/batch-core";
import { getValidator } from "../validator-singleton.js";

// Re-export the shared types + functions so downstream server code can
// keep importing from this module without churn.
export type Delimiter = CoreDelimiter;
export type ColumnMapping = CoreColumnMapping;
export type ParsedRow = CoreParsedRow;
export type CsvParseResult = CoreCsvParseResult;
export type StreamingCsvInput = CoreStreamingCsvInput;
export type StreamingCsvParser = CoreStreamingCsvParser;

export interface CsvParseOptions {
  schemaId: string;
  columnMapping?: ColumnMapping;
  delimiter?: Delimiter;
  trimValues?: boolean;
}

/**
 * Options for the streaming parser. Mirrors {@link CsvParseOptions} and
 * adds the `maxRows` knob — the route layer threads
 * `OPENCRED_BATCH_ROW_LIMIT` through here so a slow-stream attacker
 * can't bypass the cap by buffering the body across many tiny chunks.
 */
export interface StreamingCsvParseOptions extends CsvParseOptions {
  maxRows?: number;
}

export const StreamingCsvLimitError = StreamingCsvLimitErrorCore;
export const detectDelimiter = detectDelimiterCore;
export const parseRawCsv = parseRawCsvCore;
export const applyMapping = applyMappingCore;

// The Validator is a single process-wide instance constructed during
// bootstrap (see apps/server/src/index.ts / apps/server/src/validator-singleton.ts
// and Anand's P1-01). Do not cache a Validator at module scope here —
// multiple stale copies bound to different registry snapshots was the
// original bug.

function validateRow(
  schemaId: string,
  subject: Record<string, unknown>,
): { valid: boolean; errors: Array<{ field: string; message: string }> } {
  const result: ValidationResult = getValidator().validateCredentialSubject(schemaId, subject);
  return {
    valid: result.valid,
    errors: result.errors.map((e) => ({ field: e.field ?? "unknown", message: e.message })),
  };
}

/**
 * Parse CSV text and validate each row against the server's schema
 * registry. Wraps `@opencred/batch-core`'s `parseCsv` with the injected
 * schema validator.
 *
 * This is the legacy buffered API — it materialises every row in memory
 * before returning. Callers that handle large CSVs (the batch route)
 * should prefer {@link parseCsvStreaming} which yields rows one at a
 * time and bounds resident memory by the size of the longest row.
 */
export function parseCsv(csv: string, options: CsvParseOptions): CsvParseResult {
  const coreOptions: CoreCsvParseOptions = {
    schemaId: options.schemaId,
    columnMapping: options.columnMapping,
    delimiter: options.delimiter,
    trimValues: options.trimValues,
    validate: validateRow,
  };
  return parseCsvCore(csv, coreOptions);
}

/**
 * Construct a streaming CSV parser for the batch route (issue #446 Tier 2
 * item #7). Returns the shared {@link StreamingCsvParser} handle — call
 * `headers()` once, then iterate `rows()` to drain the body.
 *
 * The `input` may be a `string` (legacy JSON-body callers), a single
 * `Uint8Array`, or an `AsyncIterable<Uint8Array>` (the streaming case —
 * `c.req.raw.body` from Hono is exactly this shape via Web Streams).
 *
 * `maxRows` is mandatory in spirit: the route always passes
 * `OPENCRED_BATCH_ROW_LIMIT` so a slow-stream attacker can't bypass the
 * cap by drip-feeding bytes. Pass `undefined` only in tests or callers
 * that have already enforced the cap upstream.
 */
export function parseCsvStreaming(
  input: StreamingCsvInput,
  options: StreamingCsvParseOptions,
): StreamingCsvParser {
  const coreOptions: CoreStreamingCsvOptions = {
    schemaId: options.schemaId,
    columnMapping: options.columnMapping,
    delimiter: options.delimiter,
    trimValues: options.trimValues,
    validate: validateRow,
    maxRows: options.maxRows,
  };
  return streamingParseCsvCore(input, coreOptions);
}
