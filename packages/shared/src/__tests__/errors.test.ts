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

  it("SchemaValidationError includes validation errors in JSON", () => {
    const err = new SchemaValidationError("schema mismatch", [
      { field: "name", message: "required" },
    ]);
    const json = err.toJSON();
    expect(json.error.validationErrors).toHaveLength(1);
    expect(err.statusCode).toBe(400);
  });
});
