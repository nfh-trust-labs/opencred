/**
 * Tests for logger key-material redaction.
 *
 * These test the security-critical redaction functions that strip
 * private key material before log data reaches disk.
 */

import { describe, it, expect } from "vitest";
import { redact, redactValue, redactBuffer } from "../main/logger.js";

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

  it("preserves DIDs — they are public identifiers and must remain in logs", () => {
    // DIDs look like base64url to the regex, but the protect-then-redact pass preserves them
    const did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const result = redact(did);
    expect(result).toBe(did);
  });

  it("does NOT redact URLs (skipped because they contain ://)", () => {
    const url = "https://example.com/very/long/path/that/is/more/than/forty/characters/long";
    const result = redact(url);
    // URLs are detected via the `://` scheme separator and skipped wholesale
    expect(result).toBe(url);
  });

  it("does NOT redact short base64 strings", () => {
    const short = "SGVsbG8gV29ybGQ="; // "Hello World" in base64 (16 chars)
    expect(redact(short)).toBe(short);
  });

  it("redacts long base64url strings (no + char) (#330)", () => {
    // base64url alphabet: [A-Za-z0-9_-]
    // This is the shape of a JWK d field payload — the case #330 covers.
    const b64url = "MHQCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5GkMnNaWPKyho_-";
    const result = redact(b64url);
    expect(result).toBe("[REDACTED]");
  });

  it("redacts long base64url strings with mixed alphabet (#330)", () => {
    const key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    expect(redact(key)).toBe("[REDACTED]");
  });

  it("redacts JWK d field in single-quoted object literals (#330)", () => {
    // Some error messages serialise objects with single quotes.
    const msg = "Failed to parse {'d':'longsecretprivatekey','x':'abc'}";
    const result = redact(msg);
    expect(result).not.toContain("longsecretprivatekey");
    expect(result).toContain("'d':'[REDACTED]'");
  });

  it("redacts URL-encoded d= parameter (#330)", () => {
    const urlForm = "d=abcDEF123_-xyz456&x=publicpart";
    const result = redact(urlForm);
    expect(result).toContain("d=[REDACTED]");
    expect(result).not.toContain("abcDEF123_-xyz456");
    expect(result).toContain("x=publicpart");
  });

  it("does NOT redact absolute filesystem paths with extensions", () => {
    const path =
      "/Users/someone/opencred/.claude/worktrees/agent-xyz/apps/desktop/dist/preload/main/preload.cjs";
    const result = redact(path);
    expect(result).toBe(path);
  });

  it("does NOT redact log output referencing a Windows-style path", () => {
    const path = "C:\\\\Users\\\\me\\\\AppData\\\\Roaming\\\\opencred\\\\config.json";
    expect(redact(path)).toBe(path);
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

  it("redacts base64url key material nested in objects (#330)", () => {
    const obj = {
      keyId: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      privateKeyD: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
    };
    const result = redactValue(obj) as Record<string, unknown>;
    // DID stays readable
    expect(result.keyId).toContain("did:key:z6Mk");
    // Base64url payload is redacted
    expect(result.privateKeyD).toBe("[REDACTED]");
  });

  it("redacts Buffer values to length-only summary (#330)", () => {
    const buf = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const result = redactValue(buf);
    expect(result).toBe("[BUFFER len=10]");
  });

  it("redacts Uint8Array values to length-only summary (#330)", () => {
    const arr = new Uint8Array([1, 2, 3, 4, 5]);
    const result = redactValue(arr);
    expect(result).toBe("[BUFFER len=5]");
  });
});

describe("redactBuffer", () => {
  it("returns length-only summary for a Buffer", () => {
    const buf = Buffer.alloc(32);
    expect(redactBuffer(buf)).toBe("[BUFFER len=32]");
  });

  it("returns length-only summary for a Uint8Array", () => {
    const arr = new Uint8Array(16);
    expect(redactBuffer(arr)).toBe("[BUFFER len=16]");
  });
});
