import { describe, it, expect } from "vitest";
import { assertJwtSize, MAX_JWT_BYTES } from "../jwt-size.js";
import { PayloadTooLargeError } from "../errors.js";

describe("assertJwtSize", () => {
  it("accepts a normal-sized JWT", () => {
    const jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6a2V5OnoxIn0.abc123";
    expect(() => assertJwtSize(jwt)).not.toThrow();
  });

  it("accepts a JWT exactly at the size limit", () => {
    const jwt = "a".repeat(MAX_JWT_BYTES);
    expect(() => assertJwtSize(jwt)).not.toThrow();
  });

  it("rejects a JWT exceeding the size limit", () => {
    const jwt = "a".repeat(MAX_JWT_BYTES + 1);
    expect(() => assertJwtSize(jwt)).toThrow(PayloadTooLargeError);
  });

  it("includes the size limit in the error message", () => {
    const jwt = "a".repeat(MAX_JWT_BYTES + 1);
    expect(() => assertJwtSize(jwt)).toThrow(`${MAX_JWT_BYTES}`);
  });

  it("accepts an empty string", () => {
    expect(() => assertJwtSize("")).not.toThrow();
  });

  it("measures multi-byte characters correctly", () => {
    // Each emoji is 4 bytes in UTF-8; create a string that is under
    // MAX_JWT_BYTES in character count but over in byte count.
    const charsNeeded = Math.ceil(MAX_JWT_BYTES / 4) + 1;
    const oversized = "\u{1F600}".repeat(charsNeeded);
    expect(() => assertJwtSize(oversized)).toThrow(PayloadTooLargeError);
  });
});

describe("MAX_JWT_BYTES", () => {
  it("is 1 MiB", () => {
    expect(MAX_JWT_BYTES).toBe(1_048_576);
  });
});
