import { describe, it, expect, afterEach, vi } from "vitest";
import { Hono } from "hono";
import {
  OpenCredError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  CryptoError,
  SchemaValidationError,
} from "@opencred/shared";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

interface ErrorBody {
  error: {
    code: string;
    message: string;
    validationErrors?: unknown[];
  };
}

const logger = makeTestLogger();

function createTestApp(throwError: () => never) {
  const app = new Hono();
  app.get("/test", () => {
    throwError();
  });
  app.onError(errorHandler(logger));
  return app;
}

describe("Error handler middleware", () => {
  it("maps ValidationError to 400", async () => {
    const app = createTestApp(() => {
      throw new ValidationError("Bad input");
    });
    const res = await app.request("/test");
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.message).toBe("Bad input");
  });

  it("maps AuthenticationError to 401", async () => {
    const app = createTestApp(() => {
      throw new AuthenticationError();
    });
    const res = await app.request("/test");
    expect(res.status).toBe(401);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("AUTHENTICATION_ERROR");
  });

  it("maps AuthorizationError to 403", async () => {
    const app = createTestApp(() => {
      throw new AuthorizationError();
    });
    const res = await app.request("/test");
    expect(res.status).toBe(403);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("AUTHORIZATION_ERROR");
  });

  it("maps NotFoundError to 404", async () => {
    const app = createTestApp(() => {
      throw new NotFoundError();
    });
    const res = await app.request("/test");
    expect(res.status).toBe(404);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("NOT_FOUND");
  });

  it("maps RateLimitError to 429", async () => {
    const app = createTestApp(() => {
      throw new RateLimitError();
    });
    const res = await app.request("/test");
    expect(res.status).toBe(429);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("RATE_LIMIT_EXCEEDED");
  });

  it("maps CryptoError to 500", async () => {
    const app = createTestApp(() => {
      throw new CryptoError("Key derivation failed");
    });
    const res = await app.request("/test");
    expect(res.status).toBe(500);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("CRYPTO_ERROR");
  });

  it("maps SchemaValidationError with validation details", async () => {
    const app = createTestApp(() => {
      throw new SchemaValidationError("Schema invalid", [{ field: "name", error: "required" }]);
    });
    const res = await app.request("/test");
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("SCHEMA_VALIDATION_ERROR");
    expect(body.error.validationErrors).toHaveLength(1);
  });

  it("maps unknown errors to 500 without leaking details", async () => {
    const app = createTestApp(() => {
      throw new Error("some internal secret path /etc/keys/private.pem");
    });
    const res = await app.request("/test");
    expect(res.status).toBe(500);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("INTERNAL_ERROR");
    expect(body.error.message).toBe("An unexpected error occurred");
    expect(JSON.stringify(body)).not.toContain("private.pem");
  });


  // ── Stack trace suppression by NODE_ENV ─────────────────────────

  describe("stack trace suppression", () => {
    const originalNodeEnv = process.env.NODE_ENV;

    afterEach(() => {
      process.env.NODE_ENV = originalNodeEnv;
    });

    it("omits stack trace from logged error info in production", async () => {
      process.env.NODE_ENV = "production";
      const spyLogger = makeTestLogger();
      const logged: Record<string, unknown>[] = [];
      vi.spyOn(spyLogger, "error").mockImplementation(
        (obj: unknown, ..._args: unknown[]) => {
          logged.push(obj as Record<string, unknown>);
        },
      );

      const app = new Hono();
      app.get("/test", () => {
        throw new Error("boom");
      });
      app.onError(errorHandler(spyLogger));

      await app.request("/test");

      expect(logged.length).toBeGreaterThan(0);
      const errInfo = logged[0]!.err as { message: string; stack?: string };
      expect(errInfo.message).toBe("boom");
      expect(errInfo).not.toHaveProperty("stack");
    });

    it("includes stack trace in logged error info in development", async () => {
      process.env.NODE_ENV = "development";
      const spyLogger = makeTestLogger();
      const logged: Record<string, unknown>[] = [];
      vi.spyOn(spyLogger, "error").mockImplementation(
        (obj: unknown, ..._args: unknown[]) => {
          logged.push(obj as Record<string, unknown>);
        },
      );

      const app = new Hono();
      app.get("/test", () => {
        throw new Error("boom");
      });
      app.onError(errorHandler(spyLogger));

      await app.request("/test");

      expect(logged.length).toBeGreaterThan(0);
      const errInfo = logged[0]!.err as { message: string; stack?: string };
      expect(errInfo.message).toBe("boom");
      expect(errInfo).toHaveProperty("stack");
      expect(errInfo.stack).toContain("Error: boom");
    });
  });

  it("maps generic OpenCredError with custom status code", async () => {
    const app = createTestApp(() => {
      throw new OpenCredError("Custom error", "CUSTOM_CODE", 418);
    });
    const res = await app.request("/test");
    expect(res.status).toBe(418);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("CUSTOM_CODE");
  });
});
