import type { Context, Next } from "hono";
import { PayloadTooLargeError } from "@opencred/shared";

export interface BodyLimitOptions {
  /** Maximum allowed body size in bytes.  Defaults to 1 MiB. */
  maxSize: number;
}

const DEFAULT_MAX_SIZE = 1024 * 1024; // 1 MiB

/**
 * Middleware that rejects requests whose `Content-Length` exceeds the
 * configured maximum.
 *
 * This is a lightweight pre-read check — it inspects the `Content-Length`
 * header before the body is parsed.  Requests without a `Content-Length`
 * header (e.g. chunked transfer) are allowed through; the downstream JSON
 * parser will still enforce its own limits.
 */
export function bodyLimitMiddleware(options: Partial<BodyLimitOptions> = {}) {
  const maxSize = options.maxSize ?? DEFAULT_MAX_SIZE;

  return async (c: Context, next: Next) => {
    const contentLength = c.req.header("content-length");
    if (contentLength) {
      const length = parseInt(contentLength, 10);
      if (!Number.isNaN(length) && length > maxSize) {
        throw new PayloadTooLargeError(
          `Request body exceeds maximum allowed size of ${maxSize} bytes`,
        );
      }
    }
    await next();
  };
}
