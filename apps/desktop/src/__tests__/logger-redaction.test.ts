/**
 * Tests for logger key-material redaction.
 *
 * These test the security-critical redaction functions that strip
 * private key material before log data reaches disk.
 */

import { describe, it, expect } from "vitest";
import { redact, redactValue } from "../main/logger.js";

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
    const input = "key1: -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY----- and key2: -----BEGIN EC PRIVATE KEY-----\ndef\n-----END EC PRIVATE KEY-----";
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

  it("does NOT redact long base64url strings (no + char)", () => {
    // base64url uses - and _ instead of + and / — JWK d fields catch these separately
    const b64url = "MHQCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5GkMnNaWPKyho";
    expect(redact(b64url)).toBe(b64url);
  });

  it("does NOT redact short base64 strings", () => {
    const short = "SGVsbG8gV29ybGQ="; // "Hello World" in base64 (16 chars)
    expect(redact(short)).toBe(short);
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

describe("redactValue", () => {
  it("redacts strings", () => {
    const pem = "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----";
    expect(redactValue(pem)).toBe("[REDACTED-PEM]");
  });

  it("redacts within objects", () => {
    const obj = { key: "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----", safe: "hello" };
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
