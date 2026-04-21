/**
 * Shared CSV parser for OpenCred's batch issuance pipeline.
 *
 * Extracted from `apps/server/src/batch/csv-parser.ts` +
 * `apps/desktop/src/batch/csv-parser.ts` — they previously carried
 * byte-for-byte identical implementations of delimiter detection, line
 * parsing, raw CSV parsing, and column mapping. A bug fix to one copy
 * never made it to the other; see Anand's P2-02.
 *
 * This module stays schema-engine-agnostic: callers inject the schema
 * validator via `CsvParseOptions.validate`. The previously-shared
 * `getValidator()` lookups now live in the app-level thin wrappers.
 *
 * SECURITY: No key material is ever involved in parsing.
 */

import type {
  ColumnMapping,
  CsvParseOptions,
  CsvParseResult,
  Delimiter,
  ParsedRow,
} from "./types.js";

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
    return ",";
  }

  let bestDelimiter: Delimiter = ",";
  let bestScore = -1;

  for (const candidate of DELIMITER_CANDIDATES) {
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

    const minCount = Math.min(...counts);
    const maxCount = Math.max(...counts);

    // A good delimiter appears consistently across lines.
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
// CSV parsing (RFC 4180-compatible)
// ---------------------------------------------------------------------------

/**
 * Parse a single CSV line respecting quoted fields and escaped quotes.
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
        // Escaped quote?
        if (i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i += 2;
          continue;
        }
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
 * Parse raw CSV text into headers + rows of string arrays.
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

  const headers = parseCsvLine(nonEmpty[0], delimiter).map((h) => (trim ? h.trim() : h));
  const dataRows = nonEmpty.slice(1).map((line) => {
    const values = parseCsvLine(line, delimiter);
    return trim ? values.map((v) => v.trim()) : values;
  });

  return { headers, rows: dataRows };
}

// ---------------------------------------------------------------------------
// Column mapping
// ---------------------------------------------------------------------------

/**
 * Apply column mapping to a row's raw values.
 *
 * If a column mapping is provided, the raw CSV column names are translated
 * to schema property names. If no mapping is provided, the raw headers
 * are used as-is (assuming they match the schema).
 *
 * Unmapped raw columns are included pass-through so partial mappings
 * work sensibly. See Anand's P2-01: the mappedKeys Set is built once
 * per call rather than per row.
 */
export function applyMapping(
  rawValues: Record<string, string>,
  mapping?: ColumnMapping,
): Record<string, unknown> {
  if (!mapping) return { ...rawValues };

  const mapped: Record<string, unknown> = {};
  for (const [csvCol, schemaField] of Object.entries(mapping)) {
    if (csvCol in rawValues) mapped[schemaField] = rawValues[csvCol];
  }
  const mappedKeys = new Set(Object.values(mapping));
  for (const [key, value] of Object.entries(rawValues)) {
    if (!mapping[key] && value !== "" && !mappedKeys.has(key)) {
      mapped[key] = value;
    }
  }
  return mapped;
}

// ---------------------------------------------------------------------------
// Main parse function
// ---------------------------------------------------------------------------

/**
 * Parse CSV text, apply the column mapping, and validate each row using
 * the injected `validate` callback.
 *
 * Callers in each app wire `validate` to their own schema registry —
 * the core has no opinion on schema tooling.
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
    const rawValues: Record<string, string> = {};
    for (let j = 0; j < headers.length; j++) {
      rawValues[headers[j]] = rawRow[j] ?? "";
    }

    const mappedSubject = applyMapping(rawValues, options.columnMapping);
    const verdict = options.validate(options.schemaId, mappedSubject);

    if (verdict.valid) validCount++;
    else invalidCount++;

    parsedRows.push({
      rowIndex: i,
      rawValues,
      mappedSubject,
      valid: verdict.valid,
      errors: verdict.errors,
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
