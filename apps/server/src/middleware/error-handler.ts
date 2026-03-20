/**
 * Global error handler using the OpenCredError hierarchy.
 *
 * SECURITY: Error responses never leak key material, internal paths,
 * or signing buffers. The OpenCredError hierarchy sanitizes by design.
 */

import type { Context } from "hono";
import { OpenCredError, SchemaValidationError } from "@opencred/shared";
import { getLogger } from "../logger.js";

export function errorHandler(err: Error, c: Context): Response {
  const logger = getLogger();

  if (err instanceof SchemaValidationError) {
    logger.warn({ code: err.code, message: err.message }, "Schema validation error");
    return c.json(err.toJSON(), err.statusCode as 400);
  }

  if (err instanceof OpenCredError) {
    logger.warn({ code: err.code, message: err.message }, "Application error");
    return c.json(err.toJSON(), err.statusCode as 400);
  }

  // Unknown errors — log full error but return sanitized response
  logger.error({ err: err.message }, "Unhandled error");
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
