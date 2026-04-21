/**
 * CSV parser for batch credential issuance (desktop version).
 *
 * Thin wrapper over `@opencred/batch-core` that injects the desktop
 * main-process schema validator. The parsing logic itself (delimiter
 * detection, line parsing, column mapping, applyMapping Set hoist from
 * P2-01) now lives in batch-core — see Anand's P2-02.
 *
 * Works entirely offline -- no network requests.
 *
 * SECURITY: No key material is ever involved in parsing. Only credential
 * subject data is handled here.
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
import { getValidator } from "../main/validator-singleton.js";

// Re-export the shared types + pure functions so downstream desktop code
// can keep importing from this module without churn.
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

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

// The Validator is a single process-wide instance held by
// `main/validator-singleton.ts` and constructed during bootstrap. Do not
// cache a Validator at module scope here — see Anand's P1-01.

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
 * Parse CSV text and validate each row against the desktop app's schema
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
