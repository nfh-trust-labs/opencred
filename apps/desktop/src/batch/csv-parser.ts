/**
 * CSV parser for batch credential issuance.
 *
 * Parses CSV files with auto-detection of delimiters (comma, semicolon, tab),
 * maps columns to credentialSubject fields, and validates each row against
 * a selected schema using @opencred/schema-engine.
 *
 * Works entirely offline -- no network requests.
 *
 * SECURITY: No key material is ever involved in parsing. Only credential
 * subject data is handled here.
 */

import type { ValidationResult } from "@opencred/schema-engine";
import { getValidator } from "../main/validator-singleton.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Supported delimiters for auto-detection. */
export type Delimiter = "," | ";" | "\t";

/** Configuration for mapping CSV columns to schema fields. */
export interface ColumnMapping {
  /** Maps CSV column header -> schema property name. */
  [csvColumn: string]: string;
}

/** Validation result for a single parsed row. */
export interface ParsedRow {
  /** Zero-based index of the row in the CSV file (excluding header). */
  rowIndex: number;
  /** The raw CSV values keyed by column header. */
  rawValues: Record<string, string>;
  /** The mapped credentialSubject data (after applying column mapping). */
  mappedSubject: Record<string, unknown>;
  /** Whether the row passed schema validation. */
  valid: boolean;
  /** Validation errors for this row (empty if valid). */
  errors: Array<{ field: string; message: string }>;
}

/** Result of parsing a CSV file. */
export interface CsvParseResult {
  /** The detected or specified delimiter. */
  delimiter: Delimiter;
  /** The column headers found in the CSV. */
  headers: string[];
  /** All parsed rows with validation status. */
  rows: ParsedRow[];
  /** Number of valid rows. */
  validCount: number;
  /** Number of invalid rows. */
  invalidCount: number;
  /** Total number of data rows (excluding header). */
  totalCount: number;
}

/** Options for parsing a CSV file. */
export interface CsvParseOptions {
  /** The schema ID to validate rows against. */
  schemaId: string;
  /** Column-to-schema-field mapping. If not provided, headers are used as-is. */
  columnMapping?: ColumnMapping;
  /** Force a specific delimiter instead of auto-detecting. */
  delimiter?: Delimiter;
  /** Whether to trim whitespace from values. Defaults to true. */
  trimValues?: boolean;
}

// ---------------------------------------------------------------------------
// Delimiter detection
// ---------------------------------------------------------------------------

const DELIMITER_CANDIDATES: Delimiter[] = [",", ";", "\t"];

/**
 * Auto-detect the delimiter used in a CSV string.
 *
 * Strategy: count occurrences of each candidate delimiter in the first
 * few lines. The candidate that appears most consistently wins.
 */
export function detectDelimiter(csv: string): Delimiter {
  // Take first 5 lines (or fewer if the file is shorter)
  const lines = csv
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0)
    .slice(0, 5);

  if (lines.length === 0) {
    return ","; // default
  }

  let bestDelimiter: Delimiter = ",";
  let bestScore = -1;

  for (const candidate of DELIMITER_CANDIDATES) {
    // Count occurrences in each line
    const counts = lines.map((line) => {
      let count = 0;
      let inQuotes = false;
      for (const ch of line) {
        if (ch === '"') {
          inQuotes = !inQuotes;
        } else if (ch === candidate && !inQuotes) {
          count++;
        }
      }
      return count;
    });

    // A good delimiter appears consistently across lines
    const minCount = Math.min(...counts);
    const maxCount = Math.max(...counts);

    // Score: high minimum count + low variance = good
    if (minCount > 0) {
      const consistency = minCount / Math.max(maxCount, 1);
      const score = minCount * consistency;
      if (score > bestScore) {
        bestScore = score;
        bestDelimiter = candidate;
      }
    }
  }

  return bestDelimiter;
}

// ---------------------------------------------------------------------------
// CSV parsing (simple, RFC 4180-compatible)
// ---------------------------------------------------------------------------

/**
 * Parse a CSV line respecting quoted fields.
 */
function parseCsvLine(line: string, delimiter: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;
  let i = 0;

  while (i < line.length) {
    const ch = line[i];

    if (inQuotes) {
      if (ch === '"') {
        // Check for escaped quote (double quote)
        if (i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i += 2;
          continue;
        }
        // End of quoted field
        inQuotes = false;
        i++;
        continue;
      }
      current += ch;
      i++;
    } else {
      if (ch === '"') {
        inQuotes = true;
        i++;
        continue;
      }
      if (ch === delimiter) {
        fields.push(current);
        current = "";
        i++;
        continue;
      }
      current += ch;
      i++;
    }
  }

  fields.push(current);
  return fields;
}

/**
 * Parse raw CSV text into rows of string arrays.
 *
 * Returns [headers, ...dataRows].
 */
export function parseRawCsv(
  csv: string,
  delimiter: Delimiter,
  trim = true,
): { headers: string[]; rows: string[][] } {
  const lines = csv.split(/\r?\n/);
  const nonEmpty = lines.filter((l) => l.trim().length > 0);

  if (nonEmpty.length === 0) {
    return { headers: [], rows: [] };
  }

  const headerLine = nonEmpty[0];
  const headers = parseCsvLine(headerLine, delimiter).map((h) => (trim ? h.trim() : h));

  const dataRows = nonEmpty.slice(1).map((line) => {
    const values = parseCsvLine(line, delimiter);
    return trim ? values.map((v) => v.trim()) : values;
  });

  return { headers, rows: dataRows };
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

// The Validator is a single process-wide instance held by
// `main/validator-singleton.ts` and constructed during bootstrap. Do not
// cache a Validator at module scope here — see Anand's P1-01.

/**
 * Apply column mapping to a row's raw values.
 *
 * If a column mapping is provided, the raw CSV column names are translated
 * to schema property names. If no mapping is provided, the raw headers
 * are used as-is (assuming they match the schema).
 */
function applyMapping(
  rawValues: Record<string, string>,
  mapping?: ColumnMapping,
): Record<string, unknown> {
  if (!mapping) {
    return { ...rawValues };
  }

  const mapped: Record<string, unknown> = {};
  for (const [csvCol, schemaField] of Object.entries(mapping)) {
    if (csvCol in rawValues) {
      mapped[schemaField] = rawValues[csvCol];
    }
  }

  // Anand's P2-01: mappedKeys is invariant for the whole mapping — hoist
  // the Set above the row loop. Previously this rebuilt it on every row.
  const mappedKeys = new Set(Object.values(mapping));

  // Also include any raw values whose headers are not in the mapping
  // (they pass through as-is in case the user only mapped some columns)
  for (const [key, value] of Object.entries(rawValues)) {
    if (!mapping[key] && value !== "") {
      // Only include if not already mapped under a different name
      if (!mappedKeys.has(key)) {
        mapped[key] = value;
      }
    }
  }

  return mapped;
}

/**
 * Validate a mapped credential subject against a schema.
 */
function validateRow(
  schemaId: string,
  subject: Record<string, unknown>,
): { valid: boolean; errors: Array<{ field: string; message: string }> } {
  const result: ValidationResult = getValidator().validateCredentialSubject(schemaId, subject);
  return {
    valid: result.valid,
    errors: result.errors.map((e) => ({
      field: e.field ?? "unknown",
      message: e.message,
    })),
  };
}

// ---------------------------------------------------------------------------
// Main parse function
// ---------------------------------------------------------------------------

/**
 * Parse a CSV string and validate each row against a schema.
 *
 * @param csv - The raw CSV text content.
 * @param options - Parse options including schema ID and optional column mapping.
 * @returns CsvParseResult with per-row validation status.
 */
export function parseCsv(csv: string, options: CsvParseOptions): CsvParseResult {
  const trim = options.trimValues !== false;
  const delimiter = options.delimiter ?? detectDelimiter(csv);
  const { headers, rows: rawRows } = parseRawCsv(csv, delimiter, trim);

  const parsedRows: ParsedRow[] = [];
  let validCount = 0;
  let invalidCount = 0;

  for (let i = 0; i < rawRows.length; i++) {
    const rawRow = rawRows[i];

    // Build rawValues keyed by header
    const rawValues: Record<string, string> = {};
    for (let j = 0; j < headers.length; j++) {
      rawValues[headers[j]] = rawRow[j] ?? "";
    }

    // Apply column mapping
    const mappedSubject = applyMapping(rawValues, options.columnMapping);

    // Validate against schema
    const { valid, errors } = validateRow(options.schemaId, mappedSubject);

    if (valid) {
      validCount++;
    } else {
      invalidCount++;
    }

    parsedRows.push({
      rowIndex: i,
      rawValues,
      mappedSubject,
      valid,
      errors,
    });
  }

  return {
    delimiter,
    headers,
    rows: parsedRows,
    validCount,
    invalidCount,
    totalCount: rawRows.length,
  };
}
