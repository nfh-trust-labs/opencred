/**
 * Shared CSV / batch-processing types used by both the server and desktop
 * batch pipelines.
 *
 * Extracted from `apps/server/src/batch/csv-parser.ts` +
 * `apps/desktop/src/batch/csv-parser.ts` — they previously carried
 * byte-for-byte identical definitions. See Anand's P2-02.
 */

/** Supported CSV delimiters for auto-detection. */
export type Delimiter = "," | ";" | "\t";

/** Maps CSV column header → schema property name. */
export interface ColumnMapping {
  [csvColumn: string]: string;
}

/**
 * The validation verdict for a single row in a parsed CSV. Callers
 * inject the actual schema validator via `CsvParseOptions.validate`; the
 * shape below is a narrow contract so `@opencred/batch-core` never needs
 * to depend on `@opencred/schema-engine` directly (avoids pulling AJV
 * into every package that transitively imports batch-core).
 */
export interface RowValidationVerdict {
  valid: boolean;
  errors: Array<{ field: string; message: string }>;
}

/** A parsed + validated CSV row. */
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
  /** The schema ID to validate rows against (passed through to `validate`). */
  schemaId: string;
  /** Column-to-schema-field mapping. If not provided, headers are used as-is. */
  columnMapping?: ColumnMapping;
  /** Force a specific delimiter instead of auto-detecting. */
  delimiter?: Delimiter;
  /** Whether to trim whitespace from values. Defaults to true. */
  trimValues?: boolean;
  /**
   * Callback that validates a single row's mapped subject against the
   * configured schema. Injected so the core stays agnostic of the
   * schema-engine implementation. Must return `{ valid, errors }`.
   */
  validate: (schemaId: string, subject: Record<string, unknown>) => RowValidationVerdict;
}

// ---------------------------------------------------------------------------
// Batch engine — row-level progress types (shared between desktop + server)
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
  /** Whether the batch is currently running. */
  running: boolean;
  /** Whether the batch was cancelled. */
  cancelled: boolean;
}
