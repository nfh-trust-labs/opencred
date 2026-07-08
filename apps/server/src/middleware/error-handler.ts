/**
 * Global error handler using the OpenCredError hierarchy.
 *
 * SECURITY: Error responses never leak key material, internal paths,
 * or signing buffers. The OpenCredError hierarchy sanitizes by design.
 */

import type { Context } from "hono";
import { OpenCredError, SchemaValidationError } from "@opencred/shared";
import { getLogger } from "../logger.js";

/**
 * Duck-type detection for OpenCredError instances that crossed a realm
 * boundary (vi.mock, worker thread, re-serialized error). `instanceof`
 * is unreliable in those cases; checking for the shape preserves the
 * sanitized-response contract when something synthetic (or a cross-realm
 * instance) comes through.
 */
function isOpenCredErrorShape(e: unknown): e is OpenCredError {
  return (
    typeof e === "object" &&
    e !== null &&
    "code" in e &&
    typeof (e as { code: unknown }).code === "string" &&
    "statusCode" in e &&
    typeof (e as { statusCode: unknown }).statusCode === "number" &&
    "toJSON" in e &&
    typeof (e as { toJSON: unknown }).toJSON === "function"
  );
}

export function errorHandler(err: Error, c: Context): Response {
  const logger = getLogger();

  if (err instanceof SchemaValidationError) {
    logger.warn({ code: err.code, message: err.message }, "Schema validation error");
    return c.json(err.toJSON(), err.statusCode as 400);
  }

  if (err instanceof OpenCredError || isOpenCredErrorShape(err)) {
    const ocErr = err as OpenCredError;
    logger.warn({ code: ocErr.code, message: ocErr.message }, "Application error");
    return c.json(ocErr.toJSON(), ocErr.statusCode as 400);
  }

  // Malformed JSON request bodies are now mapped to 400 INVALID_JSON at the
  // route layer via `parseJsonBody` (apps/server/src/middleware/parse-json.ts),
  // which throws a `MalformedJsonError`. That error flows through the
  // `OpenCredError` branch above, so this handler no longer needs a
  // SyntaxError-stack-frame heuristic. SyntaxErrors raised deeper inside
  // route handlers (e.g. `JSON.parse` of an inline credential payload) keep
  // the existing 500/INTERNAL_ERROR path — they are server-side or unexpected-
  // input bugs, not malformed request bodies.

  // Unknown errors — log the full Error via Pino's default serializer so
  // the stack trace, name, and any custom props land in the structured
  // JSON stream. The previous `{ err: err.message }` shape threw away the
  // stack. The HTTP response stays the same sanitized 500 — this affects
  // only the server log. See Anand's P3-01.
  logger.error({ err }, "Unhandled error");
  return c.json(
    {
      error: {
        code: "INTERNAL_ERROR",
        message: "An internal error occurred",
      },
    },
    500,
  );
}
