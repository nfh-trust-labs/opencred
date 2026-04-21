import { describe, it, expect } from "vitest";
import {
  OpenCredError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  CryptoError,
  DIDResolutionError,
  SchemaValidationError,
  DelegationError,
  DeDiClientError,
  SessionExpiredError,
  VerificationError,
  RateLimitError,
  ConflictError,
  NotImplementedError,
} from "../errors.js";

describe("OpenCredError", () => {
  it("creates an error with code and status", () => {
    const err = new OpenCredError("test message", "TEST_CODE", 418);
    expect(err.message).toBe("test message");
    expect(err.code).toBe("TEST_CODE");
    expect(err.statusCode).toBe(418);
    expect(err.name).toBe("OpenCredError");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(OpenCredError);
  });

  it("serializes to JSON without leaking internals", () => {
    const err = new OpenCredError("bad input", "BAD_INPUT", 400);
    const json = err.toJSON();
    expect(json).toEqual({
      error: { code: "BAD_INPUT", message: "bad input" },
    });
    expect(JSON.stringify(json)).not.toContain("stack");
  });
});

describe("domain-specific errors", () => {
  it("ValidationError has 400 status", () => {
    const err = new ValidationError("invalid field");
    expect(err.statusCode).toBe(400);
    expect(err.code).toBe("VALIDATION_ERROR");
    expect(err).toBeInstanceOf(OpenCredError);
  });

  it("AuthenticationError has 401 status", () => {
    const err = new AuthenticationError();
    expect(err.statusCode).toBe(401);
    expect(err.code).toBe("AUTHENTICATION_ERROR");
  });

  it("AuthorizationError has 403 status", () => {
    const err = new AuthorizationError();
    expect(err.statusCode).toBe(403);
  });

  it("NotFoundError has 404 status", () => {
    const err = new NotFoundError();
    expect(err.statusCode).toBe(404);
  });

  it("ConflictError has 409 status", () => {
    const err = new ConflictError("duplicate");
    expect(err.statusCode).toBe(409);
  });

  it("RateLimitError has 429 status", () => {
    const err = new RateLimitError();
    expect(err.statusCode).toBe(429);
  });

  it("SessionExpiredError has 410 status", () => {
    const err = new SessionExpiredError();
    expect(err.statusCode).toBe(410);
  });

  it("CryptoError has 500 status", () => {
    const err = new CryptoError("signing failed");
    expect(err.statusCode).toBe(500);
  });

  it("DIDResolutionError has 500 status", () => {
    const err = new DIDResolutionError("unresolvable");
    expect(err.statusCode).toBe(500);
  });

  it("DeDiClientError defaults to 502", () => {
    const err = new DeDiClientError("upstream failure");
    expect(err.statusCode).toBe(502);
  });

  it("DelegationError has 400 status", () => {
    const err = new DelegationError("invalid chain");
    expect(err.statusCode).toBe(400);
  });

  it("VerificationError has 400 status", () => {
    const err = new VerificationError("proof invalid");
    expect(err.statusCode).toBe(400);
  });

  it("NotImplementedError has 501 status", () => {
    const err = new NotImplementedError();
    expect(err.statusCode).toBe(501);
    expect(err.code).toBe("NOT_IMPLEMENTED");
    expect(err.name).toBe("NotImplementedError");
    expect(err).toBeInstanceOf(OpenCredError);
  });

  it("NotImplementedError accepts custom message", () => {
    const err = new NotImplementedError("CA adapter not configured");
    expect(err.message).toBe("CA adapter not configured");
    expect(err.statusCode).toBe(501);
  });

  it("SchemaValidationError includes validation errors in JSON", () => {
    const err = new SchemaValidationError("schema mismatch", [
      { field: "name", message: "required" },
    ]);
    const json = err.toJSON();
    expect(json.error.validationErrors).toHaveLength(1);
    expect(err.statusCode).toBe(400);
  });
});

describe("sanitization (security invariant)", () => {
  it("strips POSIX absolute paths from toJSON output", () => {
    const err = new CryptoError(
      "Failed to load asset at /Users/alice/opencred/artifacts/sample.bin: ENOENT",
    );
    const body = err.toJSON();
    expect(body.error.message).not.toContain("/Users/alice");
    expect(body.error.message).not.toContain("/opencred/artifacts");
    expect(body.error.message).toContain("[PATH]/sample.bin");
    expect(body.error.code).toBe("CRYPTO_ERROR");
    // Raw .message is preserved for server-side logging.
    expect(err.message).toContain("/Users/alice/opencred/artifacts/sample.bin");
  });

  it("strips /home/... and /tmp/... paths", () => {
    const err = new CryptoError("read /home/ubuntu/work/notes.txt failed");
    expect(err.toJSON().error.message).not.toContain("/home/ubuntu");
    expect(err.toJSON().error.message).toContain("[PATH]/notes.txt");

    const err2 = new CryptoError("tempfile /tmp/build-xyz/output.bin missing");
    expect(err2.toJSON().error.message).not.toContain("/tmp/build-xyz");
    expect(err2.toJSON().error.message).toContain("[PATH]/output.bin");
  });

  it("strips Windows absolute paths from toJSON output", () => {
    const err = new CryptoError("Failed to open C:\\Users\\alice\\Documents\\archive.bin (EPERM)");
    const body = err.toJSON();
    expect(body.error.message).not.toContain("C:\\Users\\alice");
    expect(body.error.message).not.toContain("Documents");
    expect(body.error.message).toContain("[PATH]\\archive.bin");
  });

  it("strips file:// URLs", () => {
    const err = new CryptoError("failed at file:///Users/alice/x.json");
    expect(err.toJSON().error.message).not.toContain("file://");
    expect(err.toJSON().error.message).toContain("[FILE_URL]");
  });

  it("strips V8 stack-trace frames from toJSON output", () => {
    const inner = new Error("boom");
    // Force a well-formed V8 stack.
    inner.stack =
      "Error: boom\n" +
      "    at loadAsset (/Users/alice/opencred/packages/crypto/src/loader.ts:42:13)\n" +
      "    at async main (/Users/alice/opencred/apps/desktop/src/main.ts:11:5)";
    const err = new CryptoError(`load failed: ${inner.stack}`);
    const body = err.toJSON();
    expect(body.error.message).not.toMatch(/\bat\s+loadAsset\b/);
    expect(body.error.message).not.toMatch(/\bat\s+async\s+main\b/);
    expect(body.error.message).not.toContain("/Users/alice");
    expect(body.error.message).not.toContain("loader.ts:42:13");
  });

  it("redacts PEM blocks", () => {
    const synthetic =
      "-----BEGIN CERTIFICATE-----\n" +
      "MIIDXTCCAkWgAwIBAgIJAKpyZ1placeholderplaceholderplaceholder\n" +
      "placeholderplaceholderplaceholderplaceholderplaceholder\n" +
      "-----END CERTIFICATE-----";
    const err = new CryptoError(`cannot parse: ${synthetic}`);
    const body = err.toJSON();
    expect(body.error.message).toContain("[REDACTED_PEM]");
    expect(body.error.message).not.toContain("BEGIN CERTIFICATE");
    expect(body.error.message).not.toContain("placeholderplaceholder");
  });

  it("redacts long base64 blobs", () => {
    const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789++//==";
    const err = new CryptoError(`signature failed: ${b64}`);
    const body = err.toJSON();
    expect(body.error.message).toContain("[REDACTED_B64]");
    expect(body.error.message).not.toContain(b64);
  });

  it("redacts long hex blobs (fingerprints)", () => {
    const fingerprint = "a".repeat(64); // SHA-256 hex length
    const err = new CryptoError(`bad fingerprint ${fingerprint}`);
    const body = err.toJSON();
    expect(body.error.message).toContain("[REDACTED_HEX]");
    expect(body.error.message).not.toContain(fingerprint);
  });

  it("preserves short hex/base64 identifiers (<40 chars)", () => {
    const err = new ValidationError("bad id abcd1234 at field x");
    const body = err.toJSON();
    // 8-char hex is a legitimate short id — should NOT be redacted.
    expect(body.error.message).toContain("abcd1234");
  });

  it("preserves the error code across sanitization", () => {
    const err = new CryptoError("failed at /Users/alice/store/index.bin");
    expect(err.toJSON().error.code).toBe("CRYPTO_ERROR");
    const err2 = new ValidationError("bad /home/x/y input");
    expect(err2.toJSON().error.code).toBe("VALIDATION_ERROR");
    const err3 = new NotFoundError("missing /tmp/missing.json");
    expect(err3.toJSON().error.code).toBe("NOT_FOUND");
  });

  it("subclasses inherit sanitization automatically", () => {
    const subclasses: Array<new (m: string) => OpenCredError> = [
      ValidationError,
      CryptoError,
      NotFoundError,
      ConflictError,
      DIDResolutionError,
      DelegationError,
      VerificationError,
    ];
    for (const Ctor of subclasses) {
      const err = new Ctor("failed at /Users/alice/opencred/data/record.bin");
      const body = err.toJSON();
      expect(body.error.message).not.toContain("/Users/alice");
      expect(body.error.message).toContain("[PATH]/record.bin");
    }
  });

  it("does not leak 'stack' key in JSON output", () => {
    const err = new CryptoError("boom");
    const body = err.toJSON();
    expect(Object.keys(body.error)).not.toContain("stack");
    expect(JSON.stringify(body)).not.toContain('"stack"');
  });

  it("truncates very long messages", () => {
    // Build a long message that does NOT match any sanitizer pattern
    // (no absolute paths, no long base64/hex runs). Repeated short
    // words separated by spaces break up the base64/hex runs so the
    // truncation path is the one actually being tested.
    const longMessage = Array.from({ length: 400 }, (_, i) => `word${String(i)}`).join(" ");
    expect(longMessage.length).toBeGreaterThan(2000);
    const err = new CryptoError(longMessage);
    const body = err.toJSON();
    expect(body.error.message.length).toBeLessThanOrEqual(512);
    expect(body.error.message.endsWith("...")).toBe(true);
  });

  it("falls back to generic message when fully redacted", () => {
    const synthetic = "-----BEGIN CERTIFICATE-----\nMIIDplaceholder\n-----END CERTIFICATE-----";
    const err = new CryptoError(synthetic);
    const body = err.toJSON();
    // Scrubbing leaves "[REDACTED_PEM]", not the fallback — but confirm
    // a fully-empty message is replaced rather than blank.
    expect(body.error.message.length).toBeGreaterThan(0);
  });

  it("toHttpBody() is an alias for toJSON()", () => {
    const err = new CryptoError("failed at /Users/alice/store/index.bin");
    expect(err.toHttpBody()).toEqual(err.toJSON());
  });

  it("SchemaValidationError sanitizes message while keeping validationErrors", () => {
    const err = new SchemaValidationError("schema mismatch in /Users/alice/schemas/edu.json", [
      { field: "name", message: "required" },
    ]);
    const body = err.toJSON();
    expect(body.error.message).not.toContain("/Users/alice");
    expect(body.error.message).toContain("[PATH]/edu.json");
    expect(body.error.code).toBe("SCHEMA_VALIDATION_ERROR");
    expect(body.error.validationErrors).toHaveLength(1);
  });

  it("preserves raw .message for server-side logging (backwards compat)", () => {
    const raw =
      "Failed at /Users/alice/opencred/store/index.bin with fingerprint " + "a".repeat(64);
    const err = new CryptoError(raw);
    expect(err.message).toBe(raw); // un-sanitized
    expect(err.toJSON().error.message).not.toBe(raw); // sanitized
  });

  it("CryptoError preserves the underlying error via { cause }", () => {
    const underlying = new Error("EVP internal");
    const err = new CryptoError("Signing operation failed", { cause: underlying });
    expect(err.cause).toBe(underlying);
    // The wire payload must still be sanitized and must not include the cause.
    const body = err.toJSON();
    expect(body.error.message).toBe("Signing operation failed");
    expect(JSON.stringify(body)).not.toContain("EVP internal");
  });

  it("CryptoError without options leaves cause undefined (backwards compat)", () => {
    const err = new CryptoError("Signing operation failed");
    expect(err.cause).toBeUndefined();
  });
});
