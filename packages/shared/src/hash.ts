import { createHash } from "node:crypto";

/**
 * Canonical SHA-256 of a JSON value.
 *
 * Serializes the input using recursive sorted-key JSON, then hashes the
 * UTF-8 bytes with SHA-256. Returns a lowercase hex digest.
 *
 * This function is the contract between the opencred-vc-schemas hash-pinner
 * script and the monorepo build script. Both MUST produce bit-identical
 * output for the same input, or builds will hard-fail on hash mismatch.
 *
 * Rules:
 * - Object keys are sorted lexicographically at every level.
 * - Arrays preserve input order.
 * - `undefined` values and keys with `undefined` values are dropped (same as JSON.stringify).
 * - `null` is serialized as "null".
 * - NaN and ±Infinity throw — not representable in JSON.
 * - -0 is serialized as "0" (canonical numeric representation).
 * - Unicode strings are encoded as UTF-8 bytes before hashing (Node default).
 * - Non-plain-object non-array values (functions, symbols, etc.) throw.
 */
export function canonicalJsonSha256(value: unknown): string {
  const canonical = canonicalize(value);
  if (canonical === undefined) {
    throw new TypeError("canonicalJsonSha256: top-level value is undefined");
  }
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

function canonicalize(value: unknown): string | undefined {
  if (value === null) return "null";

  const t = typeof value;

  if (t === "undefined") return undefined;

  if (t === "function" || t === "symbol" || t === "bigint") {
    throw new TypeError(
      `canonicalJsonSha256: unsupported value of type ${t}`,
    );
  }

  if (t === "number") {
    const n = value as number;
    if (!Number.isFinite(n)) {
      throw new TypeError(
        "canonicalJsonSha256: NaN and Infinity are not representable in JSON",
      );
    }
    // Canonicalize -0 as "0".
    if (Object.is(n, -0)) return "0";
    return JSON.stringify(n);
  }

  if (t === "string" || t === "boolean") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const parts = value.map((el) => {
      const s = canonicalize(el);
      // JSON.stringify serializes undefined array elements as null.
      return s === undefined ? "null" : s;
    });
    return `[${parts.join(",")}]`;
  }

  if (t === "object") {
    // Reject non-plain objects (Date, Map, Set, class instances, etc.)
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError(
        "canonicalJsonSha256: only plain objects are supported",
      );
    }
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const s = canonicalize(obj[k]);
      if (s === undefined) continue; // drop undefined values
      parts.push(`${JSON.stringify(k)}:${s}`);
    }
    return `{${parts.join(",")}}`;
  }

  throw new TypeError(`canonicalJsonSha256: unsupported value of type ${t}`);
}
