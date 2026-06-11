import { describe, it, expect } from "vitest";
import {
  applyMapping,
  detectDelimiter,
  parseCsv,
  parseRawCsv,
  type RowValidationVerdict,
} from "../index.js";

function alwaysValid(): RowValidationVerdict {
  return { valid: true, errors: [] };
}

describe("detectDelimiter", () => {
  it("detects comma", () => {
    expect(detectDelimiter("name,degree\nAlice,BS")).toBe(",");
  });

  it("detects semicolon", () => {
    expect(detectDelimiter("name;degree\nAlice;BS")).toBe(";");
  });

  it("detects tab", () => {
    expect(detectDelimiter("name\tdegree\nAlice\tBS")).toBe("\t");
  });

  it("defaults to comma for empty input", () => {
    expect(detectDelimiter("")).toBe(",");
  });
});

describe("parseRawCsv", () => {
  it("parses basic comma-delimited CSV", () => {
    const { headers, rows } = parseRawCsv("a,b\n1,2", ",");
    expect(headers).toEqual(["a", "b"]);
    expect(rows).toEqual([["1", "2"]]);
  });

  it("handles quoted fields with commas", () => {
    const { rows } = parseRawCsv('a,b\n"Doe, Jane","MIT, Cambridge"', ",");
    expect(rows[0]).toEqual(["Doe, Jane", "MIT, Cambridge"]);
  });

  it("handles escaped quotes", () => {
    const { rows } = parseRawCsv('a\n"she said ""hi"""', ",");
    expect(rows[0][0]).toBe('she said "hi"');
  });

  it("skips empty lines", () => {
    const { rows } = parseRawCsv("a\nA\n\nB", ",");
    expect(rows).toEqual([["A"], ["B"]]);
  });

  it("handles CRLF line endings", () => {
    const { rows } = parseRawCsv("a\r\nA\r\nB", ",");
    expect(rows).toEqual([["A"], ["B"]]);
  });

  it("trims when trim=true", () => {
    const { rows } = parseRawCsv(" a , b \n A , B ", ",", true);
    expect(rows).toEqual([["A", "B"]]);
  });
});

describe("applyMapping", () => {
  it("passes through when no mapping is provided", () => {
    const out = applyMapping({ name: "A", role: "B" });
    expect(out).toEqual({ name: "A", role: "B" });
  });

  it("translates CSV column headers to schema field names", () => {
    const out = applyMapping(
      { "Full Name": "Alice", Occupation: "grower" },
      { "Full Name": "name", Occupation: "role" },
    );
    expect(out).toEqual({ name: "Alice", role: "grower" });
  });

  it("includes unmapped non-empty raw values (pass-through)", () => {
    const out = applyMapping({ name: "A", extra: "x" }, { name: "name" });
    expect(out).toEqual({ name: "A", extra: "x" });
  });

  it("skips unmapped raw columns whose header collides with a mapped schema field", () => {
    // raw 'name' already takes the mapped slot; a raw 'role' must not shadow it.
    const out = applyMapping(
      { "Full Name": "Alice", role: "should-not-appear" },
      { "Full Name": "role" },
    );
    expect(out).toEqual({ role: "Alice" });
  });

  it("hoists the mappedKeys Set once per call (behavioural equivalence — P2-01)", () => {
    // Sanity: a mapping producing identical input/output stays stable under
    // many rows without allocating per-row.
    const mapping = { a: "A", b: "B" };
    const rows = Array.from({ length: 1000 }, (_, i) => ({ a: String(i), b: "x" }));
    const outs = rows.map((r) => applyMapping(r, mapping));
    expect(outs.length).toBe(1000);
    expect(outs[0]).toEqual({ A: "0", B: "x" });
    expect(outs[999]).toEqual({ A: "999", B: "x" });
  });
});

describe("parseCsv", () => {
  it("parses + validates with the injected callback", () => {
    const result = parseCsv("a,b\n1,2\n3,4", {
      schemaId: "test",
      validate: alwaysValid,
    });
    expect(result.totalCount).toBe(2);
    expect(result.validCount).toBe(2);
    expect(result.rows[0].mappedSubject).toEqual({ a: "1", b: "2" });
  });

  it("propagates validation errors onto each row", () => {
    const result = parseCsv("a,b\n1,2\n3,4", {
      schemaId: "test",
      validate: (_id, subject) => {
        if ((subject as { a?: string }).a === "3") {
          return { valid: false, errors: [{ field: "a", message: "nope" }] };
        }
        return alwaysValid();
      },
    });
    expect(result.validCount).toBe(1);
    expect(result.invalidCount).toBe(1);
    expect(result.rows[1].errors).toEqual([{ field: "a", message: "nope" }]);
  });

  it("honours an explicit delimiter override", () => {
    const result = parseCsv("a;b\n1;2", {
      schemaId: "test",
      delimiter: ";",
      validate: alwaysValid,
    });
    expect(result.delimiter).toBe(";");
    expect(result.validCount).toBe(1);
  });

  it("preserves row indices from input order", () => {
    const result = parseCsv("a\n1\n2\n3", { schemaId: "test", validate: alwaysValid });
    expect(result.rows.map((r) => r.rowIndex)).toEqual([0, 1, 2]);
  });
});
