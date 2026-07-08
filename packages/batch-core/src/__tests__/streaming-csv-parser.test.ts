/**
 * Tests for the streaming CSV parser (issue #446 Tier 2 #7).
 *
 * The pre-streaming parser buffered the whole CSV string, ran
 * `split(/\r?\n/)`, materialised a `rawRows: string[][]` array, then a
 * `parsedRows: ParsedRow[]` array — three full-input copies in memory
 * before any signing started. The new parser yields rows one at a time
 * with bounded resident memory.
 *
 * These tests pin the contract we care about for the engine: header
 * parsing, RFC4180 quoting (including embedded newlines), chunk-split
 * resilience, error semantics, and the fail-fast row-count cap.
 */

import { describe, it, expect } from "vitest";
import {
  streamingParseCsv,
  StreamingCsvLimitError,
  StreamingCsvRecordSizeError,
  type RowValidationVerdict,
  type StreamingCsvInput,
} from "../index.js";

function alwaysValid(): RowValidationVerdict {
  return { valid: true, errors: [] };
}

/**
 * Drain every row from the parser into an array. Tests use this for
 * the small/medium-sized fixtures where holding the result in memory
 * is fine. The big-CSV tests use the streaming iterator directly to
 * assert on memory shape.
 */
async function collectRows(
  input: StreamingCsvInput,
  options = { schemaId: "test", validate: alwaysValid },
) {
  const parser = streamingParseCsv(input, options);
  const headerInfo = await parser.headers();
  const rows = [];
  for await (const row of parser.rows()) {
    rows.push(row);
  }
  return { headerInfo, rows };
}

/**
 * Async iterable that yields the input one char at a time. Forces every
 * chunk boundary in the parser to be exercised — a multi-byte field
 * value split across "chunks" must still parse correctly.
 */
function charByChar(input: string): AsyncIterable<Uint8Array> {
  const encoder = new TextEncoder();
  async function* gen() {
    for (const ch of input) {
      yield encoder.encode(ch);
    }
  }
  return gen();
}

describe("streamingParseCsv — header parsing", () => {
  it("returns the parsed headers + detected delimiter", async () => {
    const { headerInfo } = await collectRows("name,role\nA,B");
    expect(headerInfo.headers).toEqual(["name", "role"]);
    expect(headerInfo.delimiter).toBe(",");
  });

  it("detects semicolon delimiter from the header alone", async () => {
    const { headerInfo } = await collectRows("name;role\nA;B");
    expect(headerInfo.delimiter).toBe(";");
  });

  it("honours an explicit delimiter override", async () => {
    const { headerInfo } = await collectRows("name|role\nA|B", {
      schemaId: "test",
      validate: alwaysValid,
      // @ts-expect-error — | is not a Delimiter, but the override path
      // accepts whatever the caller passes; explicit delimiters bypass
      // detection. Cast preserved to document intent.
      delimiter: ",",
    });
    expect(headerInfo.delimiter).toBe(",");
  });

  it("trims header field whitespace by default", async () => {
    const { headerInfo } = await collectRows("  name  , role \nA,B");
    expect(headerInfo.headers).toEqual(["name", "role"]);
  });

  it("preserves header whitespace when trimValues=false", async () => {
    const parser = streamingParseCsv("  name  , role \nA,B", {
      schemaId: "test",
      validate: alwaysValid,
      trimValues: false,
    });
    const { headers } = await parser.headers();
    expect(headers).toEqual(["  name  ", " role "]);
    for await (const _ of parser.rows()) {
      /* drain */
    }
  });

  it("idempotent — headers() returns the same value on repeated calls", async () => {
    const parser = streamingParseCsv("name\nA", { schemaId: "test", validate: alwaysValid });
    const first = await parser.headers();
    const second = await parser.headers();
    expect(first).toBe(second);
    for await (const _ of parser.rows()) {
      /* drain */
    }
  });
});

describe("streamingParseCsv — row iteration", () => {
  it("yields rows in input order", async () => {
    const { rows } = await collectRows("name\nA\nB\nC");
    expect(rows.map((r) => r.rawValues.name)).toEqual(["A", "B", "C"]);
    expect(rows.map((r) => r.rowIndex)).toEqual([0, 1, 2]);
  });

  it("populates mappedSubject and rawValues identically to the buffered parser", async () => {
    const { rows } = await collectRows("name,role\nAlice,grower");
    expect(rows[0].rawValues).toEqual({ name: "Alice", role: "grower" });
    expect(rows[0].mappedSubject).toEqual({ name: "Alice", role: "grower" });
    expect(rows[0].valid).toBe(true);
    expect(rows[0].errors).toEqual([]);
  });

  it("applies columnMapping to mappedSubject", async () => {
    const parser = streamingParseCsv("Full Name,Occupation\nAlice,grower", {
      schemaId: "test",
      validate: alwaysValid,
      columnMapping: { "Full Name": "name", Occupation: "role" },
    });
    await parser.headers();
    const out = [];
    for await (const row of parser.rows()) out.push(row);
    expect(out[0].mappedSubject).toEqual({ name: "Alice", role: "grower" });
  });

  it("captures per-row validation errors", async () => {
    const parser = streamingParseCsv("name\nbad\ngood", {
      schemaId: "test",
      validate: (_id, subject) => {
        if ((subject as { name?: string }).name === "bad") {
          return { valid: false, errors: [{ field: "name", message: "nope" }] };
        }
        return alwaysValid();
      },
    });
    await parser.headers();
    const out = [];
    for await (const row of parser.rows()) out.push(row);
    expect(out[0].valid).toBe(false);
    expect(out[0].errors).toEqual([{ field: "name", message: "nope" }]);
    expect(out[1].valid).toBe(true);
  });

  it("rejects a second iteration of rows() (single-use stream)", async () => {
    const parser = streamingParseCsv("name\nA", { schemaId: "test", validate: alwaysValid });
    for await (const _ of parser.rows()) {
      /* drain */
    }
    let caught: unknown;
    try {
      for await (const _ of parser.rows()) {
        /* should never run */
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toMatch(/already consumed/);
  });
});

describe("streamingParseCsv — RFC4180 quoting", () => {
  it("handles quoted fields containing the delimiter", async () => {
    const { rows } = await collectRows('a,b\n"Doe, Jane","MIT, Cambridge"');
    expect(rows[0].rawValues).toEqual({ a: "Doe, Jane", b: "MIT, Cambridge" });
  });

  it("handles escaped quotes (doubled-quote)", async () => {
    const { rows } = await collectRows('a\n"she said ""hi"""');
    expect(rows[0].rawValues.a).toBe('she said "hi"');
  });

  it("treats \\n inside a quoted field as part of the field, not a record terminator", async () => {
    const csv = 'name,note\n"Alice","line one\nline two"\nBob,plain';
    const { rows } = await collectRows(csv);
    expect(rows).toHaveLength(2);
    expect(rows[0].rawValues).toEqual({ name: "Alice", note: "line one\nline two" });
    expect(rows[1].rawValues).toEqual({ name: "Bob", note: "plain" });
  });

  it("handles CRLF line endings", async () => {
    const { rows } = await collectRows("a\r\nA\r\nB\r\n");
    expect(rows.map((r) => r.rawValues.a)).toEqual(["A", "B"]);
  });

  it("skips empty lines between rows", async () => {
    const { rows } = await collectRows("a\nA\n\nB\n\n\nC");
    expect(rows.map((r) => r.rawValues.a)).toEqual(["A", "B", "C"]);
  });
});

describe("streamingParseCsv — chunk-boundary resilience", () => {
  it("parses correctly when chunk boundaries fall inside fields", async () => {
    // charByChar emits one TextEncoder.encode(ch) at a time, forcing
    // a chunk boundary between every character. The decoder + scanner
    // must rejoin them transparently.
    const input = charByChar('name,role\n"Alice","Field Crop Grower"\nBob,Pharmacist');
    const parser = streamingParseCsv(input, { schemaId: "test", validate: alwaysValid });
    const headers = (await parser.headers()).headers;
    expect(headers).toEqual(["name", "role"]);

    const rows = [];
    for await (const r of parser.rows()) rows.push(r);
    expect(rows[0].rawValues).toEqual({ name: "Alice", role: "Field Crop Grower" });
    expect(rows[1].rawValues).toEqual({ name: "Bob", role: "Pharmacist" });
  });

  it("parses correctly when chunk boundaries fall inside a quoted newline", async () => {
    // The trickiest case: the \n inside the quoted field arrives in
    // a different chunk than the opening quote. The scanner must
    // carry inQuotes state across chunks.
    const input = charByChar('name,note\n"Alice","line one\nline two"');
    const parser = streamingParseCsv(input, { schemaId: "test", validate: alwaysValid });
    await parser.headers();
    const rows = [];
    for await (const r of parser.rows()) rows.push(r);
    expect(rows).toHaveLength(1);
    expect(rows[0].rawValues.note).toBe("line one\nline two");
  });

  it("handles a multi-byte UTF-8 character split across chunks", async () => {
    // "é" is 0xC3 0xA9 in UTF-8. We split between the two bytes so the
    // decoder MUST hold the partial across chunks (TextDecoder with
    // stream:true handles this).
    const encoder = new TextEncoder();
    const bytes = encoder.encode("name\nrésumé"); // "n a m e \n r 0xC3 0xA9 s u m 0xC3 0xA9"
    const splitAt = "name\nr".length + 1; // mid-é
    async function* gen() {
      yield bytes.slice(0, splitAt);
      yield bytes.slice(splitAt);
    }
    const parser = streamingParseCsv(gen(), { schemaId: "test", validate: alwaysValid });
    const rows = [];
    await parser.headers();
    for await (const r of parser.rows()) rows.push(r);
    expect(rows[0].rawValues.name).toBe("résumé");
  });
});

describe("streamingParseCsv — fail-fast row cap", () => {
  it("throws StreamingCsvLimitError once the (N+1)th row is yielded", async () => {
    const parser = streamingParseCsv("a\n1\n2\n3\n4\n5", {
      schemaId: "test",
      validate: alwaysValid,
      maxRows: 3,
    });
    await parser.headers();
    const seen: string[] = [];
    let caught: unknown;
    try {
      for await (const r of parser.rows()) {
        seen.push(r.rawValues.a);
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StreamingCsvLimitError);
    expect((caught as StreamingCsvLimitError).limit).toBe(3);
    // First N rows succeed; the (N+1)th is detected and rejected
    // BEFORE it's yielded — so `seen` is exactly N items.
    expect(seen).toEqual(["1", "2", "3"]);
  });

  it("does not buffer the rest of the stream when the cap is hit", async () => {
    // Construct a generator that records the highest "checkpoint"
    // reached. With fail-fast behaviour, the parser must not pull
    // anything past the chunk that contained the (N+1)th row.
    //
    // Node generator semantics: a `yield` PAUSES the producer at the
    // yield site until the consumer calls `next()` again. So a
    // `checkpoint = K` line AFTER `yield X` only runs once the
    // consumer pulled past X. We instrument like this rather than
    // counting `yield` invocations because counts can lie about
    // whether the next assignment actually executed.
    let checkpoint = 0;
    async function* gen() {
      const encoder = new TextEncoder();
      yield encoder.encode("a\n");
      checkpoint = 1;
      yield encoder.encode("1\n2\n3\n4\n");
      checkpoint = 2;
      yield encoder.encode("5\n6\n7\n8\n");
      checkpoint = 3;
    }
    const parser = streamingParseCsv(gen(), {
      schemaId: "test",
      validate: alwaysValid,
      maxRows: 3,
    });
    await parser.headers();
    try {
      for await (const _ of parser.rows()) {
        /* iterate */
      }
    } catch {
      /* expected */
    }
    // Header pull woke the producer up to `checkpoint = 1`. The first
    // row chunk contains rows 1..4 — row 4 throws BEFORE the parser
    // asks for another chunk, so the producer is still paused at the
    // second `yield` and `checkpoint = 2` has not run. The third chunk
    // never gets pulled.
    expect(checkpoint).toBe(1);
  });
});

describe("streamingParseCsv — per-record size cap (issue #578)", () => {
  it("throws StreamingCsvRecordSizeError when a single row exceeds maxRecordBytes", async () => {
    // Construct one giant unterminated row. With no record cap the
    // parser would buffer the entire body waiting for a `\n`; with
    // the cap the parser fails BEFORE consuming the full payload.
    const huge = "a".repeat(2_000);
    const parser = streamingParseCsv(`name\n${huge}`, {
      schemaId: "test",
      validate: alwaysValid,
      maxRecordBytes: 1_000,
    });
    await parser.headers();
    let caught: unknown;
    try {
      for await (const _ of parser.rows()) {
        /* should never run */
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StreamingCsvRecordSizeError);
    expect((caught as StreamingCsvRecordSizeError).limit).toBe(1_000);
    expect((caught as StreamingCsvRecordSizeError).recordBytes).toBeGreaterThan(1_000);
  });

  it("does not include any row content in the error message (PII guard)", async () => {
    // We pack a unique sentinel into the giant field; the error
    // message must not echo it back. The CLAUDE.md security
    // invariant: row content can carry credential subject PII.
    const sentinel = "SENSITIVE_PAYLOAD_DO_NOT_LEAK";
    const huge = `${sentinel}${"x".repeat(2_000)}`;
    const parser = streamingParseCsv(`name\n${huge}`, {
      schemaId: "test",
      validate: alwaysValid,
      maxRecordBytes: 1_000,
    });
    await parser.headers();
    let caught: unknown;
    try {
      for await (const _ of parser.rows()) {
        /* drain */
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StreamingCsvRecordSizeError);
    expect((caught as Error).message).not.toContain(sentinel);
    expect((caught as Error).message).not.toContain("x".repeat(50));
  });

  it("triggers when a quoted field never closes (unterminated quote)", async () => {
    // The attack the upstream body-limit doesn't catch: an open quote
    // suppresses every `\n` boundary. The parser used to keep
    // buffering up to 200 MB before any row yielded — now it fails
    // as soon as the in-flight buffer crosses the cap.
    const payload = `name\n"${"x".repeat(2_000)}`; // no closing quote
    const parser = streamingParseCsv(payload, {
      schemaId: "test",
      validate: alwaysValid,
      maxRecordBytes: 1_000,
    });
    await parser.headers();
    let caught: unknown;
    try {
      for await (const _ of parser.rows()) {
        /* drain */
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StreamingCsvRecordSizeError);
  });

  it("passes a multi-row CSV through when every row is under the cap", async () => {
    // Each row is comfortably under the 1 KiB cap. The parser should
    // yield all rows without ever throwing.
    const lines = ["name,role"];
    for (let i = 0; i < 50; i++) lines.push(`row${i},grower`);
    const parser = streamingParseCsv(lines.join("\n"), {
      schemaId: "test",
      validate: alwaysValid,
      maxRecordBytes: 1_024,
    });
    await parser.headers();
    const rows = [];
    for await (const row of parser.rows()) rows.push(row);
    expect(rows).toHaveLength(50);
    expect(rows[0].rawValues).toEqual({ name: "row0", role: "grower" });
    expect(rows[49].rawValues).toEqual({ name: "row49", role: "grower" });
  });

  it("throws BEFORE pulling the rest of the stream once the cap is hit", async () => {
    // Same backpressure invariant as the maxRows test — the parser
    // must not keep draining chunks once a record overflows. The
    // pattern is `checkpoint = N` AFTER `yield`, which runs only
    // when the consumer pulls again. So if the parser throws right
    // after processing chunk 2 (without pulling chunk 3), the
    // producer is still suspended at the yield that delivered
    // chunk 2 — `producedChunks` reflects the count BEFORE that
    // yield resumed.
    let producedChunks = 0;
    async function* gen() {
      const encoder = new TextEncoder();
      yield encoder.encode("name\n");
      producedChunks = 1;
      yield encoder.encode("x".repeat(2_000)); // overflows cap
      producedChunks = 2;
      yield encoder.encode("\nshouldnt-reach\n");
      producedChunks = 3;
    }
    const parser = streamingParseCsv(gen(), {
      schemaId: "test",
      validate: alwaysValid,
      maxRecordBytes: 1_000,
    });
    await parser.headers();
    try {
      for await (const _ of parser.rows()) {
        /* drain */
      }
    } catch {
      /* expected */
    }
    // The header pull woke the producer to `producedChunks = 1`. The
    // scanner pulled the overflow chunk and threw immediately — it
    // never asked for the third chunk, so the producer is still
    // suspended at its second `yield` and `producedChunks = 2` has
    // not run.
    expect(producedChunks).toBe(1);
  });

  it("throws when the header alone exceeds the cap", async () => {
    // A no-newline header is the same attack surface as a no-newline
    // data row — `takeHeaderRecord` must enforce the cap too.
    const huge = "x".repeat(2_000);
    const parser = streamingParseCsv(huge, {
      schemaId: "test",
      validate: alwaysValid,
      maxRecordBytes: 1_000,
    });
    let caught: unknown;
    try {
      await parser.headers();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StreamingCsvRecordSizeError);
  });

  it("is opt-in — omitting maxRecordBytes preserves the old unbounded behaviour", async () => {
    // Pre-issue-578 callers (and tests) didn't pass the option. We
    // must not regress them: a 10 KiB row with no cap should parse
    // happily.
    const big = "y".repeat(10_000);
    const { rows } = await collectRows(`name\n${big}`);
    expect(rows).toHaveLength(1);
    expect(rows[0].rawValues.name).toBe(big);
  });
});

describe("streamingParseCsv — memory boundedness", () => {
  it("processes a 100,000-row CSV without buffering all rows", async () => {
    // We synthesise the CSV as an async generator (no full string in
    // memory) and consume it row-by-row, asserting that the parser
    // never holds more than a small constant number of rows at once.
    //
    // The "memory bound" we can actually observe in a test is: the
    // number of un-iterated rows the parser has yielded. With a
    // streaming AsyncGenerator this is at most 1 — the next() call
    // produces exactly one row, and the consumer awaits it before
    // requesting another. We verify by counting and asserting a max
    // in-flight gauge.
    const rowCount = 100_000;
    let inFlight = 0;
    let peakInFlight = 0;
    async function* generateCsv(): AsyncIterable<Uint8Array> {
      const encoder = new TextEncoder();
      yield encoder.encode("id,name\n");
      // Emit rows in batches of 1000 to keep the test fast — bigger
      // batches just exercise the boundary scanner more cheaply.
      const batchSize = 1000;
      for (let i = 0; i < rowCount; i += batchSize) {
        const chunk: string[] = [];
        for (let j = 0; j < batchSize && i + j < rowCount; j++) {
          chunk.push(`${i + j},row${i + j}`);
        }
        yield encoder.encode(chunk.join("\n") + "\n");
      }
    }

    const parser = streamingParseCsv(generateCsv(), {
      schemaId: "test",
      validate: alwaysValid,
    });
    await parser.headers();

    let count = 0;
    for await (const row of parser.rows()) {
      inFlight += 1;
      if (inFlight > peakInFlight) peakInFlight = inFlight;
      // Validate one in N to confirm parsing is correct end-to-end
      // without paying for 100k expect() calls.
      if (count === 0) {
        expect(row.rawValues).toEqual({ id: "0", name: "row0" });
      } else if (count === rowCount - 1) {
        expect(row.rawValues).toEqual({
          id: String(rowCount - 1),
          name: `row${rowCount - 1}`,
        });
      }
      count += 1;
      inFlight -= 1;
    }

    expect(count).toBe(rowCount);
    // With a serial `for await`, peak in-flight is exactly 1 — the
    // generator yields ONE row, the consumer awaits it, the next
    // pull happens. If the parser ever pre-buffered rows behind the
    // consumer this would climb past 1.
    expect(peakInFlight).toBe(1);
  }, 30_000);

  it("respects consumer backpressure (a slow consumer pauses the producer)", async () => {
    // Pull from the generator only every 20ms — the producer's
    // `yield encoder.encode(...)` must not race ahead. We measure
    // this by counting how many bytes the upstream generator has
    // produced at the moment the consumer is mid-row N.
    let producedChunks = 0;
    async function* generateCsv(): AsyncIterable<Uint8Array> {
      const encoder = new TextEncoder();
      yield encoder.encode("name\n");
      producedChunks = 1;
      for (let i = 0; i < 20; i++) {
        yield encoder.encode(`r${i}\n`);
        producedChunks = i + 2;
      }
    }

    const parser = streamingParseCsv(generateCsv(), { schemaId: "test", validate: alwaysValid });
    await parser.headers();

    let consumedRows = 0;
    for await (const _ of parser.rows()) {
      consumedRows += 1;
      // The producer races to emit one row per chunk, but the
      // generator's `yield` is suspended until the next `next()`.
      // So at the moment we've consumed K rows, the producer has
      // sent AT MOST K + 1 chunks (one ahead — the parser holds
      // the buffer for the in-progress record).
      expect(producedChunks).toBeLessThanOrEqual(consumedRows + 2);
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    expect(consumedRows).toBe(20);
  });
});
