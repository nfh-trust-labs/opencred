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
  type ColumnMapping as CoreColumnMapping,
  type CsvParseOptions as CoreCsvParseOptions,
  type CsvParseResult as CoreCsvParseResult,
  type Delimiter as CoreDelimiter,
  type ParsedRow as CoreParsedRow,
} from "@opencred/batch-core";
import { getValidator } from "../validator-singleton.js";

// Re-export the shared types + functions so downstream server code can
// keep importing from this module without churn.
export type Delimiter = CoreDelimiter;
export type ColumnMapping = CoreColumnMapping;
export type ParsedRow = CoreParsedRow;
export type CsvParseResult = CoreCsvParseResult;

export interface CsvParseOptions {
  schemaId: string;
  columnMapping?: ColumnMapping;
  delimiter?: Delimiter;
  trimValues?: boolean;
}

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
