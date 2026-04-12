import { describe, it, expect } from "vitest";
import { detectCredentialInputFormat } from "../credential-format.js";

describe("detectCredentialInputFormat", () => {
  describe("pixelpass", () => {
    it("detects OPENCRED1: prefix", () => {
      expect(detectCredentialInputFormat("OPENCRED1:someBase45data")).toBe("pixelpass");
    });

    it("detects OPENCRED1: with empty payload", () => {
      expect(detectCredentialInputFormat("OPENCRED1:")).toBe("pixelpass");
    });
  });

  describe("json", () => {
    it("detects JSON object string", () => {
      expect(detectCredentialInputFormat('{"@context":[],"type":["VerifiableCredential"]}')).toBe(
        "json",
      );
    });

    it("detects JSON with leading whitespace", () => {
      expect(detectCredentialInputFormat('  \n  {"key":"value"}')).toBe("json");
    });

    it("detects JSON with leading tab", () => {
      expect(detectCredentialInputFormat('\t{"key":"value"}')).toBe("json");
    });
  });

  describe("jwt-compact", () => {
    it("detects VC-JWT (three dot-separated base64url parts)", () => {
      expect(detectCredentialInputFormat("eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6e319.sigbytes")).toBe(
        "jwt-compact",
      );
    });

    it("detects SD-JWT (contains tilde)", () => {
      expect(
        detectCredentialInputFormat("eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6e319.sig~disclosure1~"),
      ).toBe("jwt-compact");
    });

    it("detects SD-JWT with multiple disclosures", () => {
      expect(detectCredentialInputFormat("header.payload.sig~disc1~disc2~disc3~")).toBe(
        "jwt-compact",
      );
    });
  });

  describe("unknown", () => {
    it("returns unknown for empty string", () => {
      expect(detectCredentialInputFormat("")).toBe("unknown");
    });

    it("returns unknown for random text", () => {
      expect(detectCredentialInputFormat("hello world")).toBe("unknown");
    });

    it("returns unknown for two-part dot string", () => {
      expect(detectCredentialInputFormat("header.payload")).toBe("unknown");
    });

    it("returns unknown for four-part dot string", () => {
      expect(detectCredentialInputFormat("a.b.c.d")).toBe("unknown");
    });

    it("returns unknown for three dots with empty segment", () => {
      expect(detectCredentialInputFormat("header..signature")).toBe("unknown");
    });

    it("returns unknown for three dots with non-base64url characters", () => {
      expect(detectCredentialInputFormat("hea der.pay load.sig nature")).toBe("unknown");
    });
  });

  describe("priority", () => {
    it("OPENCRED1: takes priority over JSON-like content", () => {
      expect(detectCredentialInputFormat('OPENCRED1:{"@context":[]}')).toBe("pixelpass");
    });

    it("tilde detection takes priority over dot-based JWT check", () => {
      expect(detectCredentialInputFormat("a.b.c~d")).toBe("jwt-compact");
    });
  });
});
