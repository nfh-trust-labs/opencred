/**
 * Tests for logger key-material redaction.
 *
 * These test the security-critical redaction functions that strip
 * private key material before log data reaches disk.
 */

import { describe, it, expect } from "vitest";
import { redact, redactValue, isHighEntropy } from "../main/logger.js";

describe("redact", () => {
  // -----------------------------------------------------------------------
  // PEM blocks
  // -----------------------------------------------------------------------

  it("redacts PEM private key blocks", () => {
    const pem = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5GkMnNaWP+KyhoAcGBSuBBAAi
oWQDYgAE3Qk9p2i1B5QWOQV5XfBCwJFny1TkEr5J3K8S+Gp+mhgXDY3PSNzfxyl
-----END EC PRIVATE KEY-----`;
    expect(redact(pem)).toBe("[REDACTED-PEM]");
  });

  it("redacts PEM certificate blocks", () => {
    const pem = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
-----END CERTIFICATE-----`;
    expect(redact(pem)).toBe("[REDACTED-PEM]");
  });

  it("redacts multiple PEM blocks in one string", () => {
    const input =
      "key1: -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY----- and key2: -----BEGIN EC PRIVATE KEY-----\ndef\n-----END EC PRIVATE KEY-----";
    const result = redact(input);
    expect(result).not.toContain("BEGIN");
    expect(result).toContain("[REDACTED-PEM]");
  });

  // -----------------------------------------------------------------------
  // JWK "d" fields
  // -----------------------------------------------------------------------

  it("redacts JWK d field", () => {
    const jwk = '{"kty":"EC","crv":"P-256","x":"abc","y":"def","d":"privateKeyMaterial123"}';
    const result = redact(jwk);
    expect(result).toContain('"d":"[REDACTED]"');
    expect(result).not.toContain("privateKeyMaterial123");
  });

  it("redacts JWK d field with whitespace", () => {
    const jwk = '{"d" : "somePrivateKey"}';
    const result = redact(jwk);
    expect(result).toContain("[REDACTED]");
    expect(result).not.toContain("somePrivateKey");
  });

  // -----------------------------------------------------------------------
  // Long base64 strings (key material)
  // -----------------------------------------------------------------------

  it("redacts long base64 strings containing +", () => {
    // Typical EC private key in standard base64 (contains + which triggers redaction)
    const b64key = "MHQCAQEEIBkg4LVWM9nuwNSk3yByxZp+RTBV/Jk5GkMnNaWPKyho";
    const result = redact(b64key);
    expect(result).toBe("[REDACTED]");
  });

  it("does NOT redact long alphanumeric strings without + or /", () => {
    // A DID or long identifier — pure alphanumeric, no + or /
    const did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const result = redact(did);
    expect(result).toBe(did);
  });

  it("does NOT redact URLs (no + chars)", () => {
    const url = "https://example.com/very/long/path/that/is/more/than/forty/characters/long";
    const result = redact(url);
    // URLs use / but never + in path segments, so they are not redacted
    expect(result).toBe(url);
  });

  it("redacts long base64url strings with high entropy", () => {
    // Real base64url-encoded 32-byte key — mixed case + digits + special
    const b64url = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    expect(redact(b64url)).toBe("[REDACTED]");
  });

  it("does NOT redact long pure-alphanumeric strings (no base64 special chars)", () => {
    // A transaction ID or similar identifier — pure alphanumeric, no +, /, -, or _
    const txId = "abc123def456ghi789jkl012mno345pqr678stu901vwx";
    expect(redact(txId)).toBe(txId);
  });

  it("does NOT redact short base64url strings (under 40 chars)", () => {
    const short = "abc-def_ghi";
    expect(redact(short)).toBe(short);
  });

  it("does NOT redact short base64 strings", () => {
    const short = "SGVsbG8gV29ybGQ="; // "Hello World" in base64 (16 chars)
    expect(redact(short)).toBe(short);
  });

  // -----------------------------------------------------------------------
  // False-positive resistance (base64url entropy filter)
  // -----------------------------------------------------------------------

  it("does NOT redact kebab-case build identifiers", () => {
    const id = "electron-v28-darwin-arm64-rebuild-pkcs11js-native";
    expect(redact(id)).toBe(id);
  });

  it("does NOT redact SCREAMING_SNAKE_CASE constants", () => {
    const constant = "SOME_REALLY_LONG_SNAKE_CASE_CONSTANT_NAME_USED_IN_CODE_BASE";
    expect(redact(constant)).toBe(constant);
  });

  it("does NOT redact CSS class name strings", () => {
    const css = "container-fluid-dark-theme-sidebar-navigation-wrapper";
    expect(redact(css)).toBe(css);
  });

  it("does NOT redact compound UUID strings", () => {
    const uuid = "550e8400-e29b-41d4-a716-446655440000-550e8400-e29b-41d4";
    // UUIDs are hex + hyphens — only lowercase + digits + special (2 classes)
    expect(redact(uuid)).toBe(uuid);
  });

  // -----------------------------------------------------------------------
  // Preserves safe content
  // -----------------------------------------------------------------------

  it("preserves normal log messages", () => {
    const msg = "Key imported successfully with fingerprint abc123def456";
    expect(redact(msg)).toBe(msg);
  });

  it("preserves key IDs and fingerprints", () => {
    const msg = "Using key did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP";
    expect(redact(msg)).toBe(msg);
  });

  it("preserves JSON without d field", () => {
    const json = '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}';
    expect(redact(json)).toBe(json);
  });
});

describe("isHighEntropy", () => {
  it("returns true for base64url with all 4 classes (upper + lower + digit + special)", () => {
    expect(isHighEntropy("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe(true);
  });

  it("returns false for 3 classes: lower + digit + special (no uppercase)", () => {
    expect(isHighEntropy("abc123def456-ghi789jkl012mno345pqr678stu901")).toBe(false);
  });

  it("returns false for kebab-case build identifiers (lower + digit + special)", () => {
    expect(isHighEntropy("electron-v28-darwin-arm64-rebuild-pkcs11js-native")).toBe(false);
  });

  it("returns false for SCREAMING_SNAKE (upper + special only)", () => {
    expect(isHighEntropy("SOME_REALLY_LONG_SNAKE_CASE_CONSTANT_NAME")).toBe(false);
  });

  it("returns false for lowercase-only with hyphens (2 classes)", () => {
    expect(isHighEntropy("container-fluid-dark-theme-sidebar-navigation")).toBe(false);
  });

  it("returns false for compound UUIDs (lower + digit + special, no uppercase)", () => {
    expect(isHighEntropy("550e8400-e29b-41d4-a716-446655440000-550e8400-e29b-41d4")).toBe(false);
  });
});

describe("redactValue", () => {
  it("redacts strings", () => {
    const pem = "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----";
    expect(redactValue(pem)).toBe("[REDACTED-PEM]");
  });

  it("redacts within objects", () => {
    const obj = {
      key: "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----",
      safe: "hello",
    };
    const result = redactValue(obj) as Record<string, unknown>;
    expect(result.key).toBe("[REDACTED-PEM]");
    expect(result.safe).toBe("hello");
  });

  it("passes through numbers unchanged", () => {
    expect(redactValue(42)).toBe(42);
  });

  it("passes through null unchanged", () => {
    expect(redactValue(null)).toBe(null);
  });

  it("passes through undefined unchanged", () => {
    expect(redactValue(undefined)).toBe(undefined);
  });
});
