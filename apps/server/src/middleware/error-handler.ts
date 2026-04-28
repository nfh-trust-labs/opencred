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

/**
 * Detect a JSON-parse failure raised by `c.req.json()`.
 *
 * Hono delegates body parsing to the platform's built-in `JSON.parse`, which
 * throws a plain `SyntaxError` whose message starts with one of a handful of
 * V8/JavaScriptCore phrasings ("Unexpected token …", "Expected ',' or '}' …",
 * "Unterminated string in JSON …", etc.) and whose stack contains a frame in
 * `hono/dist/request.js`. The naked `SyntaxError` constructor is reused
 * elsewhere (e.g. user code parsing a JWT segment) so we do *not* want to
 * blanket-treat every SyntaxError as a malformed body — match on the stack
 * frame to scope this narrowly. If detection ever drifts, the error will fall
 * through to the existing 500 path; nothing breaks silently.
 */
function isMalformedJsonBodyError(err: Error): boolean {
  if (err.name !== "SyntaxError") return false;
  const stack = typeof err.stack === "string" ? err.stack : "";
  return stack.includes("hono/dist/request.js") || stack.includes("hono/src/request");
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

  // Map malformed JSON request bodies to a clean 400 INVALID_JSON instead of
  // a 500. Hono's `c.req.json()` propagates a `SyntaxError` from the
  // underlying JSON.parse — without this branch the user sees a generic
  // INTERNAL_ERROR for what is unambiguously a client problem (e.g. an
  // unescaped quote inside a Postman variable expansion). The error message
  // is passed through because it's `SyntaxError`'s own description of where
  // the parser choked — no internal paths or secrets ride along.
  if (isMalformedJsonBodyError(err)) {
    logger.warn({ message: err.message }, "Malformed JSON body");
    return c.json(
      {
        error: {
          code: "INVALID_JSON",
          message: `Request body is not valid JSON: ${err.message}`,
        },
      },
      400,
    );
  }

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
