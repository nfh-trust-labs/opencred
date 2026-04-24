/**
 * Regression tests for P1-01 — validator-singleton fails loud when it is
 * used before bootstrap. Prior to the fix, five modules each lazily
 * constructed their own Validator around a `getSchemaRegistry()` that
 * silently fell back to a fresh bundled-only registry; the module that
 * raced first won forever. Now the singleton throws with a clear message so
 * misordered bootstrap cannot silently diverge.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { createRegistry, Validator } from "@opencred/schema-engine";
import { parseCsv } from "../batch/csv-parser.js";
import {
  getSchemaRegistry,
  setSchemaRegistry,
  resetSchemaRegistry,
} from "../schema-registry-singleton.js";
import { getValidator, setValidator, resetValidator } from "../validator-singleton.js";

beforeEach(() => {
  resetSchemaRegistry();
  resetValidator();
});

describe("schema-registry-singleton — P1-01", () => {
  it("throws a clear message when getSchemaRegistry is called before setSchemaRegistry", () => {
    expect(() => getSchemaRegistry()).toThrow(/Schema registry not initialized/);
  });

  it("returns the registry once setSchemaRegistry has been called", () => {
    const r = createRegistry();
    setSchemaRegistry(r);
    expect(getSchemaRegistry()).toBe(r);
  });

  it("can be reset for tests", () => {
    setSchemaRegistry(createRegistry());
    resetSchemaRegistry();
    expect(() => getSchemaRegistry()).toThrow(/Schema registry not initialized/);
  });
});

describe("validator-singleton — P1-01", () => {
  it("throws a clear message when getValidator is called before setValidator", () => {
    expect(() => getValidator()).toThrow(/Validator not initialized/);
  });

  it("returns the validator once setValidator has been called", () => {
    const r = createRegistry();
    const v = new Validator(r);
    setValidator(v);
    expect(getValidator()).toBe(v);
  });

  it("can be reset for tests", () => {
    setValidator(new Validator(createRegistry()));
    resetValidator();
    expect(() => getValidator()).toThrow(/Validator not initialized/);
  });
});

describe("parseCsv — P1-01 regression", () => {
  it("fails loud when invoked before validator bootstrap (no silent divergence)", () => {
    expect(() =>
      parseCsv("name,role,validFrom\nAlice,Grower,2025-06-01T00:00:00Z", {
        schemaId: "functional-identity/v1",
      }),
    ).toThrow(/Validator not initialized/);
  });

  it("parses successfully once bootstrap has set both the registry and the validator", () => {
    const r = createRegistry();
    setSchemaRegistry(r);
    setValidator(new Validator(r));
    const result = parseCsv("name,role,validFrom\nAlice,Field Crop Grower,2025-06-01T00:00:00Z", {
      schemaId: "functional-identity/v1",
    });
    expect(result.totalCount).toBe(1);
    expect(result.validCount).toBe(1);
  });
});
