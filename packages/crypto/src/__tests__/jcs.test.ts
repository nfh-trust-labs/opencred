import { describe, it, expect } from "vitest";
import { jcsCanonicalize, computeRevocationHash } from "../jcs.js";

describe("jcsCanonicalize (RFC 8785)", () => {
  it("should canonicalize a simple object with sorted keys", () => {
    const result = jcsCanonicalize({ b: 2, a: 1 });
    expect(result).toBe('{"a":1,"b":2}');
  });

  it("should canonicalize nested objects", () => {
    const result = jcsCanonicalize({ z: { b: 2, a: 1 }, a: true });
    expect(result).toBe('{"a":true,"z":{"a":1,"b":2}}');
  });

  it("should handle arrays (order preserved)", () => {
    const result = jcsCanonicalize({ arr: [3, 1, 2] });
    expect(result).toBe('{"arr":[3,1,2]}');
  });

  it("should handle null values", () => {
    const result = jcsCanonicalize({ a: null, b: 1 });
    expect(result).toBe('{"a":null,"b":1}');
  });

  it("should handle empty objects", () => {
    expect(jcsCanonicalize({})).toBe("{}");
  });

  it("should handle empty arrays", () => {
    expect(jcsCanonicalize([])).toBe("[]");
  });

  it("should handle unicode strings", () => {
    // RFC 8785 requires proper Unicode handling
    const result = jcsCanonicalize({ name: "\u20ac" }); // Euro sign
    expect(result).toContain("\u20ac");
  });

  it("should handle number formatting per RFC 8785", () => {
    // RFC 8785: integers are represented without decimal point
    expect(jcsCanonicalize({ n: 1 })).toBe('{"n":1}');
    // Floating point
    expect(jcsCanonicalize({ n: 1.5 })).toBe('{"n":1.5}');
  });

  it("should handle boolean values", () => {
    expect(jcsCanonicalize({ t: true, f: false })).toBe(
      '{"f":false,"t":true}'
    );
  });

  it("should handle string escaping", () => {
    const result = jcsCanonicalize({ s: 'hello "world"' });
    expect(result).toBe('{"s":"hello \\"world\\""}');
  });

  it("should produce deterministic output", () => {
    const obj = { c: 3, a: 1, b: { y: 25, x: 24 } };
    const r1 = jcsCanonicalize(obj);
    const r2 = jcsCanonicalize(obj);
    expect(r1).toBe(r2);
  });
});

describe("computeRevocationHash", () => {
  it("should produce a hex SHA-256 hash", () => {
    const hash = computeRevocationHash({ id: "test" });
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should produce consistent hash for same input", () => {
    const obj = { type: "VerifiableCredential", id: "urn:uuid:123" };
    expect(computeRevocationHash(obj)).toBe(computeRevocationHash(obj));
  });

  it("should produce same hash regardless of property order", () => {
    const obj1 = { a: 1, b: 2 };
    const obj2 = { b: 2, a: 1 };
    expect(computeRevocationHash(obj1)).toBe(computeRevocationHash(obj2));
  });

  it("should produce different hash for different input", () => {
    expect(computeRevocationHash({ a: 1 })).not.toBe(
      computeRevocationHash({ a: 2 })
    );
  });
});
