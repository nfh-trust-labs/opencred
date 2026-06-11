import { describe, it, expect } from "vitest";
import {
  jcsCanonicalize,
  computeRevocationHash,
  extractRevocationHashFromStatusId,
  resolveRevocationHash,
} from "../jcs.js";

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
    expect(jcsCanonicalize({ t: true, f: false })).toBe('{"f":false,"t":true}');
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
    expect(computeRevocationHash({ a: 1 })).not.toBe(computeRevocationHash({ a: 2 }));
  });
});

describe("extractRevocationHashFromStatusId", () => {
  const HEX = "a".repeat(64);

  it("extracts the hash from the last path segment of credentialStatus.id", () => {
    const vc = {
      credentialStatus: {
        id: `https://dedi.example/dedi/lookup/issuers.example.org/${HEX}`,
      },
    };
    expect(extractRevocationHashFromStatusId(vc)).toBe(HEX);
  });

  it("returns null when the credential has no credentialStatus", () => {
    expect(extractRevocationHashFromStatusId({ id: "urn:uuid:x" })).toBeNull();
  });

  it("returns null when credentialStatus has no id", () => {
    expect(extractRevocationHashFromStatusId({ credentialStatus: {} })).toBeNull();
  });

  it("returns null when id is not a valid URL", () => {
    expect(
      extractRevocationHashFromStatusId({
        credentialStatus: { id: "not-a-url" },
      }),
    ).toBeNull();
  });

  it("returns null when the last path segment is not a 64-char lowercase hex string", () => {
    expect(
      extractRevocationHashFromStatusId({
        credentialStatus: { id: "https://example.com/status/SHORT" },
      }),
    ).toBeNull();
    // Uppercase hex — strict match
    expect(
      extractRevocationHashFromStatusId({
        credentialStatus: { id: `https://example.com/x/${"A".repeat(64)}` },
      }),
    ).toBeNull();
    // 65 chars
    expect(
      extractRevocationHashFromStatusId({
        credentialStatus: { id: `https://example.com/x/${"a".repeat(65)}` },
      }),
    ).toBeNull();
  });

  it("returns null when the id is non-string", () => {
    expect(
      extractRevocationHashFromStatusId({ credentialStatus: { id: 42 } as unknown }),
    ).toBeNull();
    expect(
      extractRevocationHashFromStatusId({ credentialStatus: { id: null } as unknown }),
    ).toBeNull();
  });

  it("returns null for non-object inputs", () => {
    expect(extractRevocationHashFromStatusId(null)).toBeNull();
    expect(extractRevocationHashFromStatusId(undefined)).toBeNull();
    expect(extractRevocationHashFromStatusId("a string")).toBeNull();
    expect(extractRevocationHashFromStatusId(42)).toBeNull();
  });

  it("ignores trailing slashes in the URL", () => {
    const vc = {
      credentialStatus: {
        id: `https://dedi.example/dedi/lookup/namespace/${HEX}/`,
      },
    };
    expect(extractRevocationHashFromStatusId(vc)).toBe(HEX);
  });
});

describe("resolveRevocationHash", () => {
  const HEX = "b".repeat(64);

  it("prefers the hash embedded in credentialStatus.id", () => {
    const vc = {
      id: "urn:uuid:example",
      credentialStatus: {
        id: `https://dedi.example/dedi/lookup/namespace/${HEX}`,
        type: "dedi",
      },
      credentialSubject: { name: "Alice" },
    };
    expect(resolveRevocationHash(vc)).toBe(HEX);
    // NOT the canonical hash — the embedded one is authoritative.
    expect(resolveRevocationHash(vc)).not.toBe(computeRevocationHash(vc));
  });

  it("falls back to computeRevocationHash when credentialStatus.id is missing", () => {
    const vc = { id: "urn:uuid:x", credentialSubject: { name: "Bob" } };
    expect(resolveRevocationHash(vc)).toBe(computeRevocationHash(vc));
  });

  it("falls back when credentialStatus.id is malformed", () => {
    const vc = {
      credentialStatus: { id: "https://example.com/no-hash-here" },
      credentialSubject: { name: "Carol" },
    };
    expect(resolveRevocationHash(vc)).toBe(computeRevocationHash(vc));
  });
});
