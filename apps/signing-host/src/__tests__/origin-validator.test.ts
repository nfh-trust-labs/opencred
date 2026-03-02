/**
 * Tests for the origin validator.
 *
 * Validates:
 *  - Exact matching against the allowlist
 *  - Rejection of empty/null/undefined origins
 *  - No wildcard or prefix matching
 *  - Empty allowlist rejects everything
 */

import { describe, it, expect } from "vitest";
import { validateOrigin } from "../origin-validator.js";

const testAllowlist = [
  "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
  "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}",
  "chrome-extension://1234567890abcdef1234567890abcdef",
];

describe("validateOrigin", () => {
  describe("valid origins", () => {
    it("should accept an origin that is in the allowlist", () => {
      expect(
        validateOrigin("chrome-extension://abcdefghijklmnopabcdefghijklmnop", testAllowlist),
      ).toBe(true);
    });

    it("should accept another valid origin from the allowlist", () => {
      expect(
        validateOrigin("{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}", testAllowlist),
      ).toBe(true);
    });

    it("should accept the third origin in the list", () => {
      expect(
        validateOrigin("chrome-extension://1234567890abcdef1234567890abcdef", testAllowlist),
      ).toBe(true);
    });
  });

  describe("rejected origins", () => {
    it("should reject an origin not in the allowlist", () => {
      expect(validateOrigin("chrome-extension://notinlist", testAllowlist)).toBe(false);
    });

    it("should reject an empty string", () => {
      expect(validateOrigin("", testAllowlist)).toBe(false);
    });

    it("should reject a whitespace-only string", () => {
      expect(validateOrigin("   ", testAllowlist)).toBe(false);
    });

    it("should reject a partial match (prefix)", () => {
      expect(validateOrigin("chrome-extension://abcdefghijklmnop", testAllowlist)).toBe(false);
    });

    it("should reject a partial match (suffix)", () => {
      expect(validateOrigin("abcdefghijklmnopabcdefghijklmnop", testAllowlist)).toBe(false);
    });

    it("should reject a case-different origin", () => {
      expect(
        validateOrigin("Chrome-Extension://abcdefghijklmnopabcdefghijklmnop", testAllowlist),
      ).toBe(false);
    });

    it("should reject origins with trailing whitespace", () => {
      expect(
        validateOrigin("chrome-extension://abcdefghijklmnopabcdefghijklmnop ", testAllowlist),
      ).toBe(false);
    });
  });

  describe("edge cases", () => {
    it("should reject all origins when allowlist is empty", () => {
      expect(validateOrigin("chrome-extension://anything", [])).toBe(false);
    });

    it("should handle single-entry allowlist", () => {
      const single = ["chrome-extension://only-one"];
      expect(validateOrigin("chrome-extension://only-one", single)).toBe(true);
      expect(validateOrigin("chrome-extension://other", single)).toBe(false);
    });
  });
});
