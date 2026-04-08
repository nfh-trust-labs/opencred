/**
 * CSV parser for batch credential issuance (server version).
 *
 * Extracted from the desktop batch module. No Electron dependencies.
 * Parses CSV with auto-detection of delimiters, maps columns to
 * credentialSubject fields, and validates each row against a schema.
 *
 * SECURITY: No key material is ever involved in parsing.
 */

import { createRegistry, Validator } from "@opencred/schema-engine";
import type { SchemaRegistry, ValidationResult } from "@opencred/schema-engine";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Delimiter = "," | ";" | "\t";

export interface ColumnMapping {
  [csvColumn: string]: string;
}

export interface ParsedRow {
  rowIndex: number;
  rawValues: Record<string, string>;
  mappedSubject: Record<string, unknown>;
  valid: boolean;
  errors: Array<{ field: string; message: string }>;
}

export interface CsvParseResult {
  delimiter: Delimiter;
  headers: string[];
  rows: ParsedRow[];
  validCount: number;
  invalidCount: number;
  totalCount: number;
}

export interface CsvParseOptions {
  schemaId: string;
  columnMapping?: ColumnMapping;
  delimiter?: Delimiter;
  trimValues?: boolean;
}

// ---------------------------------------------------------------------------
// Delimiter detection
// ---------------------------------------------------------------------------

const DELIMITER_CANDIDATES: Delimiter[] = [",", ";", "\t"];

export function detectDelimiter(csv: string): Delimiter {
  const lines = csv
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0)
    .slice(0, 5);

  if (lines.length === 0) return ",";

  let bestDelimiter: Delimiter = ",";
  let bestScore = -1;

  for (const candidate of DELIMITER_CANDIDATES) {
    const counts = lines.map((line) => {
      let count = 0;
      let inQuotes = false;
      for (const ch of line) {
        if (ch === '"') inQuotes = !inQuotes;
        else if (ch === candidate && !inQuotes) count++;
      }
      return count;
    });

    const minCount = Math.min(...counts);
    const maxCount = Math.max(...counts);
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
// CSV parsing
// ---------------------------------------------------------------------------

function parseCsvLine(line: string, delimiter: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;
  let i = 0;

  while (i < line.length) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
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

function parseRawCsv(
  csv: string,
  delimiter: Delimiter,
  trim = true,
): { headers: string[]; rows: string[][] } {
  const lines = csv.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length === 0) return { headers: [], rows: [] };

  const headers = parseCsvLine(lines[0], delimiter).map((h) => (trim ? h.trim() : h));
  const dataRows = lines.slice(1).map((line) => {
    const values = parseCsvLine(line, delimiter);
    return trim ? values.map((v) => v.trim()) : values;
  });

  return { headers, rows: dataRows };
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

let registryInstance: SchemaRegistry | null = null;
let validatorInstance: Validator | null = null;

function getRegistry(): SchemaRegistry {
  if (!registryInstance) registryInstance = createRegistry();
  return registryInstance;
}

function getValidator(): Validator {
  if (!validatorInstance) validatorInstance = new Validator(getRegistry());
  return validatorInstance;
}

function applyMapping(
  rawValues: Record<string, string>,
  mapping?: ColumnMapping,
): Record<string, unknown> {
  if (!mapping) return { ...rawValues };

  const mapped: Record<string, unknown> = {};
  for (const [csvCol, schemaField] of Object.entries(mapping)) {
    if (csvCol in rawValues) mapped[schemaField] = rawValues[csvCol];
  }
  for (const [key, value] of Object.entries(rawValues)) {
    if (!mapping[key] && value !== "") {
      const mappedKeys = new Set(Object.values(mapping));
      if (!mappedKeys.has(key)) mapped[key] = value;
    }
  }
  return mapped;
}

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

// ---------------------------------------------------------------------------
// Main parse function
// ---------------------------------------------------------------------------

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
    const { valid, errors } = validateRow(options.schemaId, mappedSubject);

    if (valid) validCount++;
    else invalidCount++;

    parsedRows.push({ rowIndex: i, rawValues, mappedSubject, valid, errors });
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
