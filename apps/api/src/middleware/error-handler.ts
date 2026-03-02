import type { Context } from "hono";
import { OpenCredError } from "@opencred/shared";
import type { Logger } from "../logger.js";

export function errorHandler(logger: Logger) {
  return (err: Error, c: Context) => {
    if (err instanceof OpenCredError) {
      logger.warn({ code: err.code, statusCode: err.statusCode }, err.message);
      return c.json(err.toJSON(), err.statusCode as 400);
    }

    // In production, log only the error message to avoid leaking internal file paths
    // via stack traces. In development/test, include the stack for debugging.
    const errInfo = process.env.NODE_ENV === "production"
      ? { message: err.message }
      : { message: err.message, stack: err.stack };
    logger.error({ err: errInfo }, "Unhandled error");
    return c.json(
      {
        error: {
          code: "INTERNAL_ERROR",
          message: "An unexpected error occurred",
        },
      },
      500,
    );
  };
}
