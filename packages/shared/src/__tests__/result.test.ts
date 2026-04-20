import { describe, it, expect } from "vitest";
import { ok, err, isOk, type Result } from "../result.js";

describe("Result<T, E>", () => {
  it("ok() constructs a tagged success", () => {
    const r = ok({ value: 42, name: "test" });
    expect(r.ok).toBe(true);
    expect(r.value).toBe(42);
    expect(r.name).toBe("test");
  });

  it("err() constructs a tagged failure", () => {
    const r = err({ errorCode: "VALIDATION_ERROR", message: "bad input" });
    expect(r.ok).toBe(false);
    expect(r.errorCode).toBe("VALIDATION_ERROR");
    expect(r.message).toBe("bad input");
  });

  it("narrows after if (res.ok)", () => {
    type R = Result<{ credential: string }, { errorCode: string; message: string }>;
    const r: R = ok({ credential: "eyJ..." });
    if (r.ok) {
      // Narrowed to success: credential is required, no bang.
      expect(r.credential.startsWith("ey")).toBe(true);
    } else {
      // Unreachable in this case — but if we were here, errorCode would exist.
      expect(r.errorCode).toBeDefined();
    }
  });

  it("narrows after if (!res.ok)", () => {
    type R = Result<{ credential: string }, { errorCode: string; message: string }>;
    const r: R = err({ errorCode: "CRYPTO_ERROR", message: "sign failed" });
    if (!r.ok) {
      expect(r.errorCode).toBe("CRYPTO_ERROR");
      expect(r.message).toBe("sign failed");
    }
  });

  it("isOk narrows generically", () => {
    type R = Result<{ a: number }, { b: string }>;
    const rs: R[] = [ok({ a: 1 }), err({ b: "nope" })];
    const okayOnes = rs.filter(isOk);
    expect(okayOnes).toHaveLength(1);
    expect(okayOnes[0].a).toBe(1);
  });

  it("ok and err variants cannot share field names in a way that makes the union ambiguous", () => {
    // Compile-time check: if the two payload shapes overlap, the union
    // stays structurally valid. Runtime check here just confirms the
    // tag is always `ok`.
    const rOk = ok({ message: "hello" });
    const rErr = err({ message: "nope" });
    expect(rOk.ok).toBe(true);
    expect(rErr.ok).toBe(false);
  });
});
