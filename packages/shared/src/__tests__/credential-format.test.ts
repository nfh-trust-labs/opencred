import { describe, it, expect } from "vitest";
import { detectCredentialInputFormat, isPdfBytes } from "../credential-format.js";
import { encodePixelPass } from "../pixelpass.js";

describe("detectCredentialInputFormat", () => {
  describe("pixelpass", () => {
    it("detects bare PixelPass by successful decode", () => {
      // Encode a small JSON payload through PixelPass; the result is bare
      // Base45 with no prefix. Detection must still classify it.
      const payload = encodePixelPass('{"@context":["https://www.w3.org/ns/credentials/v2"]}');
      expect(detectCredentialInputFormat(payload)).toBe("pixelpass");
    });

    it("does not false-positive on an empty string", () => {
      expect(detectCredentialInputFormat("")).toBe("unknown");
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

    it("returns unknown for random text that is not PixelPass-decodable", () => {
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
    it("JSON detection takes priority over a PixelPass decode attempt", () => {
      // Leading `{` short-circuits as JSON without invoking the try-decode
      // fallback (which would also be cheap but the order is contractual).
      expect(detectCredentialInputFormat('{"@context":[]}')).toBe("json");
    });

    it("tilde detection takes priority over dot-based JWT check", () => {
      expect(detectCredentialInputFormat("a.b.c~d")).toBe("jwt-compact");
    });

    it("JWT shape is detected before falling through to PixelPass try-decode", () => {
      // A valid-looking JWT must classify as jwt-compact even if the
      // PixelPass fallback would have thrown on it anyway. This guards
      // against future regressions where the order is shuffled.
      expect(detectCredentialInputFormat("eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6e319.sig")).toBe(
        "jwt-compact",
      );
    });
  });
});

describe("isPdfBytes", () => {
  // Boundary guard for the `Content-Type: application/pdf` branch of
  // `POST /v1/credentials/verify`. Edge cases matter: false negatives
  // here turn legitimate PDF uploads into 400 BAD_REQUEST, and false
  // positives let non-PDF bytes through to pdf-lib's parser, where they
  // fail late with a less actionable message.

  it("returns true for the 5-byte PDF magic exactly", () => {
    expect(isPdfBytes(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]))).toBe(true);
  });

  it("returns true for the magic followed by a version (real-world prefix)", () => {
    // `%PDF-1.7\n` — what an actual PDF starts with.
    expect(isPdfBytes(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x0a]))).toBe(
      true,
    );
  });

  it("returns false for an empty buffer", () => {
    expect(isPdfBytes(new Uint8Array(0))).toBe(false);
  });

  it("returns false for a buffer shorter than the magic", () => {
    // `%PDF` (4 bytes) — one byte short of the magic.
    expect(isPdfBytes(new Uint8Array([0x25, 0x50, 0x44, 0x46]))).toBe(false);
  });

  it("returns false when only the first byte differs", () => {
    // Drop the leading `%`. Same length, almost the magic.
    expect(isPdfBytes(new Uint8Array([0x00, 0x50, 0x44, 0x46, 0x2d]))).toBe(false);
  });

  it("returns false for arbitrary text beginning with letters", () => {
    expect(isPdfBytes(new TextEncoder().encode("not a pdf at all"))).toBe(false);
  });

  it("returns false for JSON bytes", () => {
    expect(isPdfBytes(new TextEncoder().encode('{"@context":[]}'))).toBe(false);
  });
});
