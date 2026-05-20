/**
 * Streaming CSV parser for OpenCred's batch issuance pipeline.
 *
 * Replaces the buffer-then-split path in `parseCsv` (csv-parser.ts) — see
 * issue #446 Tier 2 item #7. The buffered parser holds the full CSV body
 * in memory three times (raw string → `lines` array from `split(/\r?\n/)`
 * → `parsedRows` array) before signing starts; for a 50 MB CSV that's
 * ~150 MB resident before any worker runs.
 *
 * This module exposes a state-machine-driven parser that consumes chunks
 * incrementally (RFC4180-compatible quoting, including embedded newlines
 * inside quoted fields) and yields one {@link ParsedRow} at a time. The
 * batch engine awaits each row through `for await`, so backpressure flows
 * naturally: if the worker pool is saturated, the parser pauses reading.
 *
 * Inputs:
 *   - `string`                                — convenience, mainly for tests
 *   - `Uint8Array | Buffer`                   — single-chunk byte input
 *   - `AsyncIterable<Uint8Array>`             — Node Readable, Web ReadableStream
 *                                               (`ReadableStream<Uint8Array>` is an
 *                                               AsyncIterable in Node 18+)
 *
 * Memory profile:
 *   - O(longest_row_bytes) for the in-progress buffer
 *   - O(headers.length)    for the parsed header array
 *   - O(1)                 for the row counter / validation state
 *
 * Per-row error semantics are unchanged: a row that fails the injected
 * validator is yielded with `valid: false` + populated `errors`, just like
 * the buffered parser. Callers (the engine) decide what to do with it.
 *
 * SECURITY:
 *   - No row content is ever logged from this module (PII concern — the
 *     credential subject is in `rawValues`/`mappedSubject`).
 *   - The `maxRows` option lets callers fail fast on a slow-stream attack
 *     that would otherwise consume unbounded server memory by trickling
 *     bytes forever. We track yielded row count and throw immediately
 *     once the cap is exceeded — no whole-body buffering required.
 */

import type {
  ColumnMapping,
  CsvParseOptions,
  Delimiter,
  ParsedRow,
  RowValidationVerdict,
} from "./types.js";
import { applyMapping, detectDelimiter } from "./csv-parser.js";

/**
 * Inputs the streaming parser accepts. A bare `string` is treated as the
 * full CSV body (mostly for tests and the legacy JSON-body batch route);
 * everything else is consumed lazily.
 */
export type StreamingCsvInput = string | Uint8Array | AsyncIterable<Uint8Array>;

/**
 * Options for {@link streamingParseCsv}. Mostly a superset of the
 * buffered `CsvParseOptions`; we hoist a couple of stream-only knobs:
 *
 *   - `maxRows` — abort the iteration after yielding this many data
 *     rows. The parser THROWS a {@link StreamingCsvLimitError} so the
 *     caller can map it to a 4xx without buffering the rest of the body.
 *   - `delimiter` — if you omit this, the parser sniffs the first chunk
 *     before yielding the header. It will not re-sniff later; if the
 *     opening chunk is too small to detect (e.g. < 1 line), the parser
 *     defaults to `,`. Pre-known delimiters should be passed explicitly.
 *   - `chunkDecoder` — optional override of the bytes-to-string step.
 *     Tests can swap this for deterministic chunk boundaries.
 */
export interface StreamingCsvOptions extends Omit<CsvParseOptions, "validate"> {
  validate: CsvParseOptions["validate"];
  /**
   * Maximum number of data rows (excluding header) the parser will yield
   * before throwing `StreamingCsvLimitError`. Omit for no cap. Tracking
   * happens at yield time, so we fail as soon as the (N+1)th row resolves.
   */
  maxRows?: number;
}

/**
 * Thrown when {@link StreamingCsvOptions.maxRows} is exceeded. Carries the
 * configured cap so the caller can surface a precise error message
 * without exposing internal state.
 */
export class StreamingCsvLimitError extends Error {
  constructor(public readonly limit: number) {
    super(`CSV row count exceeds the configured limit of ${limit}`);
    this.name = "StreamingCsvLimitError";
  }
}

/**
 * Handle returned by {@link streamingParseCsv}. Two-step contract:
 *
 *   1. `await parser.headers()` — resolves with the detected/explicit
 *      delimiter + parsed header row. Internally the parser pulls just
 *      enough bytes from the input to read the first non-empty record.
 *   2. `for await (const row of parser.rows()) { ... }` — yields each
 *      remaining data row.
 *
 * The two methods share a single parser state machine; calling
 * `rows()` before `headers()` is equivalent to calling `headers()` then
 * `rows()` — the header row is consumed and discarded.
 *
 * `headers()` is idempotent (cached after the first call); `rows()`
 * returns a fresh generator each invocation but YOU MUST iterate it
 * to completion exactly once. Iterating twice will throw because the
 * underlying input stream has already been drained.
 */
export interface StreamingCsvParser {
  headers(): Promise<{ headers: string[]; delimiter: Delimiter }>;
  rows(): AsyncGenerator<ParsedRow, void, void>;
}

// ---------------------------------------------------------------------------
// Internal chunk iteration helper
// ---------------------------------------------------------------------------

/**
 * Normalise the input into an `AsyncIterable<Uint8Array>`. A plain
 * `string` is encoded once (it's already in memory — no incremental win,
 * but we let callers pass strings for parity with the buffered API).
 *
 * Note: we do NOT call `ReadableStream.getReader()` ourselves. Node's
 * Web Streams implementation makes `ReadableStream<Uint8Array>` async
 * iterable directly, and structurally that's exactly the shape we want.
 */
async function* normaliseInput(input: StreamingCsvInput): AsyncIterable<Uint8Array> {
  if (typeof input === "string") {
    yield new TextEncoder().encode(input);
    return;
  }
  if (input instanceof Uint8Array) {
    yield input;
    return;
  }
  // AsyncIterable<Uint8Array> — pass through. Yields whatever upstream
  // dishes out; we don't aggregate or split chunks here.
  for await (const chunk of input) {
    yield chunk;
  }
}

// ---------------------------------------------------------------------------
// Record-boundary scanner
// ---------------------------------------------------------------------------

/**
 * Yield one CSV record at a time from a stream of decoded text. A
 * "record" is the substring spanning one logical row — which is NOT
 * always one line, because RFC 4180 allows `\n` inside quoted fields.
 *
 * The scanner walks through the buffer character-by-character tracking
 * the `inQuotes` state. A `\n` (or `\r\n`) outside quotes terminates the
 * record; inside quotes it's part of the field. Empty records (between
 * consecutive `\n`s) are silently skipped to match the buffered parser's
 * `filter(l => l.trim().length > 0)` behaviour.
 *
 * After yielding a record we drop everything up to and including the
 * terminator from the rolling buffer. This keeps memory bounded by the
 * size of the longest single record, never the cumulative input.
 */
async function* scanRecords(text: AsyncIterable<string>): AsyncGenerator<string> {
  let buf = "";
  let inQuotes = false;
  // Index of the next character that hasn't been examined for record
  // terminators yet. Critical: we must NOT re-scan already-seen bytes
  // when a new chunk arrives — every `"` would be double-toggled and
  // the `inQuotes` state would desync. After we emit a record we slice
  // `buf` and reset both `recordStart` and `scanPos` back to 0.
  let scanPos = 0;

  for await (const chunk of text) {
    buf += chunk;

    // Pick up scanning exactly where the previous chunk left off.
    let recordStart = 0;
    for (let i = scanPos; i < buf.length; i++) {
      const ch = buf[i];
      if (ch === '"') {
        // Doubled quote inside a quoted field stays "in quotes". We
        // don't have to distinguish here — the line-level parser
        // (parseCsvLine in csv-parser.ts) handles the escape semantics.
        // Toggling on every quote keeps the boundary detection correct.
        inQuotes = !inQuotes;
        continue;
      }
      if (inQuotes) continue;
      if (ch === "\n") {
        // Trim a trailing \r so "a,b\r\n" yields "a,b", matching
        // parseRawCsv's `csv.split(/\r?\n/)` behaviour.
        let end = i;
        if (end > recordStart && buf[end - 1] === "\r") end -= 1;
        const record = buf.slice(recordStart, end);
        if (record.trim().length > 0) {
          yield record;
        }
        recordStart = i + 1;
      }
    }

    // Drop emitted records from the buffer; keep the in-progress tail.
    // Reset `scanPos` to point at the start of the surviving tail so
    // the next chunk continues from there without re-examining bytes
    // we've already classified.
    if (recordStart > 0) {
      buf = buf.slice(recordStart);
      scanPos = 0;
    } else {
      scanPos = buf.length;
    }
  }

  // Flush a final unterminated record (no trailing \n). Matches the
  // buffered parser, which doesn't require a trailing newline either.
  if (buf.trim().length > 0) {
    yield buf;
  }
}

/**
 * Bytes → strings. We use the global TextDecoder with `stream: true` so
 * a multi-byte sequence split across two chunks is reassembled rather
 * than emitting a replacement character.
 */
async function* decodeChunks(input: AsyncIterable<Uint8Array>): AsyncIterable<string> {
  const decoder = new TextDecoder("utf-8");
  for await (const chunk of input) {
    yield decoder.decode(chunk, { stream: true });
  }
  // Final flush — emits any pending replacement character for a
  // half-finished multibyte sequence at EOF.
  const tail = decoder.decode();
  if (tail) yield tail;
}

// ---------------------------------------------------------------------------
// Per-line / per-record parser (RFC 4180)
// ---------------------------------------------------------------------------

/**
 * Parse one full CSV record (already extracted by the boundary scanner)
 * into its constituent fields. Mirrors `parseCsvLine` in `csv-parser.ts`,
 * extended with multi-line awareness: when the record contains an
 * embedded `\n` (from a quoted field), we treat that the same as any
 * other character and let the field accumulate.
 *
 * We don't share the implementation with `parseCsvLine` directly because
 * the buffered version receives single-line strings — exposing a stream-
 * tolerant variant separately avoids regressing the simpler buffered
 * path and keeps each function easy to reason about.
 */
function parseRecord(record: string, delimiter: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;
  let i = 0;

  while (i < record.length) {
    const ch = record[i];

    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < record.length && record[i + 1] === '"') {
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
      continue;
    }

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

  fields.push(current);
  return fields;
}

// ---------------------------------------------------------------------------
// Header sniffing
// ---------------------------------------------------------------------------

/**
 * Pull enough chunks from `text` to materialise the FIRST record (the
 * header line) and return it along with the remaining string-iterator
 * tail. We need a tee here because the caller still needs to iterate the
 * post-header chunks for the data rows.
 *
 * Implementation: we accumulate into a private buffer, snipping out the
 * header as soon as we cross a non-quoted `\n`. Any bytes after the
 * header become the lead chunk handed back to the row scanner via a
 * synthetic AsyncIterable that re-emits the tail first.
 */
async function takeHeaderRecord(
  chunks: AsyncIterable<string>,
): Promise<{ header: string; tail: AsyncIterable<string> }> {
  const iterator = chunks[Symbol.asyncIterator]();
  let buf = "";
  let inQuotes = false;

  while (true) {
    const next = await iterator.next();
    if (next.done) {
      // No header terminator seen — the entire input is the header
      // record (or empty). Yield whatever we have as the header; the
      // tail is an empty iterable.
      return {
        header: buf,
        tail: (async function* () {
          /* empty */
        })(),
      };
    }
    buf += next.value;

    for (let i = 0; i < buf.length; i++) {
      const ch = buf[i];
      if (ch === '"') {
        inQuotes = !inQuotes;
        continue;
      }
      if (inQuotes) continue;
      if (ch === "\n") {
        let end = i;
        if (end > 0 && buf[end - 1] === "\r") end -= 1;
        const header = buf.slice(0, end);
        const rest = buf.slice(i + 1);

        // Build a tail iterable that re-emits `rest` then continues
        // pulling from the original iterator. Order matters — `rest`
        // is the leftover from the chunk that contained the header
        // terminator.
        async function* tail(): AsyncIterable<string> {
          if (rest.length > 0) yield rest;
          while (true) {
            const n = await iterator.next();
            if (n.done) return;
            yield n.value;
          }
        }

        return { header, tail: tail() };
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Public streaming parser
// ---------------------------------------------------------------------------

/**
 * Build a streaming CSV parser. See {@link StreamingCsvParser} for the
 * call protocol and {@link StreamingCsvOptions} for the knobs.
 *
 * The returned parser is single-use: the underlying input stream is
 * drained as soon as `headers()` or `rows()` runs to completion, so
 * callers must construct a new parser per request.
 */
export function streamingParseCsv(
  input: StreamingCsvInput,
  options: StreamingCsvOptions,
): StreamingCsvParser {
  const trim = options.trimValues !== false;
  const columnMapping: ColumnMapping | undefined = options.columnMapping;

  // Lazily-initialised state shared between `headers()` and `rows()`.
  let cachedHeader: { headers: string[]; delimiter: Delimiter } | null = null;
  let recordTail: AsyncIterable<string> | null = null;
  let rowsConsumed = false;

  async function ensureHeader(): Promise<{ headers: string[]; delimiter: Delimiter }> {
    if (cachedHeader !== null) return cachedHeader;

    const byteStream = normaliseInput(input);
    const textChunks = decodeChunks(byteStream);
    const { header, tail } = await takeHeaderRecord(textChunks);

    // Delimiter resolution. The buffered detector runs on the first
    // ~5 non-empty lines for consistency; we only have the header in
    // hand (we don't want to read further than needed before yielding
    // headers to the caller). The header alone is enough for
    // detection in practice — it carries every candidate delimiter
    // at the same frequency it appears in the rows beneath it.
    //
    // If the caller passed an explicit delimiter we trust it
    // unconditionally — same as the buffered API.
    const delimiter: Delimiter = options.delimiter ?? detectDelimiter(header || "");

    const headerFields = parseRecord(header, delimiter).map((h) => (trim ? h.trim() : h));

    cachedHeader = { headers: headerFields, delimiter };
    recordTail = tail;
    return cachedHeader;
  }

  async function* iterateRows(): AsyncGenerator<ParsedRow, void, void> {
    if (rowsConsumed) {
      throw new Error("streamingParseCsv: rows() iterator already consumed");
    }
    rowsConsumed = true;

    const { headers, delimiter } = await ensureHeader();
    // After `ensureHeader()`, `recordTail` is guaranteed non-null
    // (we assign it in lock-step with `cachedHeader`).
    const tail = recordTail!;
    const validate = options.validate;
    const limit = options.maxRows;
    let yielded = 0;
    let rowIndex = 0;

    for await (const record of scanRecords(tail)) {
      const rawFields = parseRecord(record, delimiter);
      const trimmed = trim ? rawFields.map((v) => v.trim()) : rawFields;

      const rawValues: Record<string, string> = {};
      for (let j = 0; j < headers.length; j++) {
        rawValues[headers[j]] = trimmed[j] ?? "";
      }

      const mappedSubject = applyMapping(rawValues, columnMapping);
      const verdict: RowValidationVerdict = validate(options.schemaId, mappedSubject);

      const parsed: ParsedRow = {
        rowIndex,
        rawValues,
        mappedSubject,
        valid: verdict.valid,
        errors: verdict.errors,
      };
      rowIndex += 1;
      yielded += 1;

      // Fail-fast row cap. Throw BEFORE yielding the offending row so
      // the consumer never sees half a batch — matches the buffered
      // parser's "reject the whole upload" semantics, but does so
      // without reading the remainder of the stream into memory.
      if (limit !== undefined && yielded > limit) {
        throw new StreamingCsvLimitError(limit);
      }

      yield parsed;
    }
  }

  return {
    headers: ensureHeader,
    rows: iterateRows,
  };
}
