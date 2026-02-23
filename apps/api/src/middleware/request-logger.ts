import type { Context, Next } from "hono";
import type { Logger } from "../logger.js";

export function requestLogger(logger: Logger) {
  return async (c: Context, next: Next) => {
    const start = Date.now();
    const method = c.req.method;
    const path = c.req.path;
    const requestId = c.req.header("x-request-id") ?? crypto.randomUUID();

    c.set("requestId", requestId);
    c.header("X-Request-Id", requestId);

    logger.info({ method, path, requestId }, "Incoming request");

    await next();

    const duration = Date.now() - start;
    const status = c.res.status;

    logger.info({ method, path, status, duration, requestId }, "Request completed");
  };
}
