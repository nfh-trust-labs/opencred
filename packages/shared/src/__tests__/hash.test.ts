import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { canonicalJsonSha256 } from "../hash.js";

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

describe("canonicalJsonSha256", () => {
  it("hashes primitives", () => {
    expect(canonicalJsonSha256("hello")).toBe(sha256('"hello"'));
    expect(canonicalJsonSha256(42)).toBe(sha256("42"));
    expect(canonicalJsonSha256(true)).toBe(sha256("true"));
    expect(canonicalJsonSha256(false)).toBe(sha256("false"));
    expect(canonicalJsonSha256(null)).toBe(sha256("null"));
  });

  it("sorts object keys at every level", () => {
    const a = { b: 1, a: 2, c: { y: 1, x: 2 } };
    const b = { a: 2, c: { x: 2, y: 1 }, b: 1 };
    expect(canonicalJsonSha256(a)).toBe(canonicalJsonSha256(b));
  });

  it("preserves array order", () => {
    expect(canonicalJsonSha256([1, 2, 3])).not.toBe(canonicalJsonSha256([3, 2, 1]));
  });

  it("handles unicode strings", () => {
    const v = { name: "naïve 🍄 résumé" };
    expect(canonicalJsonSha256(v)).toBe(sha256('{"name":"naïve 🍄 résumé"}'));
  });

  it("treats -0 and 0 as equal", () => {
    expect(canonicalJsonSha256(-0)).toBe(canonicalJsonSha256(0));
    expect(canonicalJsonSha256({ n: -0 })).toBe(canonicalJsonSha256({ n: 0 }));
  });

  it("handles large ints and small floats", () => {
    expect(canonicalJsonSha256(1234567890)).toBe(sha256("1234567890"));
    expect(canonicalJsonSha256(0.125)).toBe(sha256("0.125"));
  });

  it("throws on NaN and Infinity", () => {
    expect(() => canonicalJsonSha256(NaN)).toThrow(TypeError);
    expect(() => canonicalJsonSha256(Infinity)).toThrow(TypeError);
    expect(() => canonicalJsonSha256(-Infinity)).toThrow(TypeError);
    expect(() => canonicalJsonSha256({ x: NaN })).toThrow(TypeError);
  });

  it("handles nested arrays and objects", () => {
    const v = {
      items: [
        { b: 2, a: 1 },
        { d: 4, c: 3 },
      ],
    };
    expect(canonicalJsonSha256(v)).toBe(sha256('{"items":[{"a":1,"b":2},{"c":3,"d":4}]}'));
  });

  it("hashes empty object and array deterministically", () => {
    expect(canonicalJsonSha256({})).toBe(sha256("{}"));
    expect(canonicalJsonSha256([])).toBe(sha256("[]"));
  });

  it("drops undefined object values (JSON.stringify behavior)", () => {
    expect(canonicalJsonSha256({ a: 1, b: undefined })).toBe(canonicalJsonSha256({ a: 1 }));
  });

  it("serializes undefined array elements as null", () => {
    expect(canonicalJsonSha256([1, undefined, 3])).toBe(canonicalJsonSha256([1, null, 3]));
  });

  it("throws on functions, symbols, bigint", () => {
    expect(() => canonicalJsonSha256(() => 0)).toThrow(TypeError);
    expect(() => canonicalJsonSha256(Symbol("x"))).toThrow(TypeError);
    expect(() => canonicalJsonSha256(BigInt(1))).toThrow(TypeError);
  });

  it("throws on non-plain objects (Date, Map, class instances)", () => {
    expect(() => canonicalJsonSha256(new Date())).toThrow(TypeError);
    expect(() => canonicalJsonSha256(new Map())).toThrow(TypeError);
    class Foo {
      x = 1;
    }
    expect(() => canonicalJsonSha256(new Foo())).toThrow(TypeError);
  });

  it("throws on top-level undefined", () => {
    expect(() => canonicalJsonSha256(undefined)).toThrow(TypeError);
  });

  // Regression fixture: locks in the canonicalization format forever.
  // If this hash ever changes, cross-repo hash pinning will break.
  it("matches pinned regression vector", () => {
    expect(canonicalJsonSha256({ id: "foo", values: [1, 2, 3] })).toBe(
      "f61ea37284382cccd62c5880c61c87a4f6d65ab16bb9923225d757c2d5509374",
    );
  });
});
