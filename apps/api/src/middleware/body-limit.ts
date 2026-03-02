import type { Context, Next } from "hono";
import { PayloadTooLargeError } from "@opencred/shared";

export interface BodyLimitOptions {
  /** Maximum allowed body size in bytes.  Defaults to 1 MiB. */
  maxSize: number;
}

const DEFAULT_MAX_SIZE = 1024 * 1024; // 1 MiB

const METHODS_WITH_BODY = new Set(["POST", "PUT", "PATCH"]);

/**
 * Middleware that rejects requests whose body exceeds the configured maximum.
 *
 * Two enforcement layers:
 * 1. **Content-Length check** — fast pre-read rejection when the header is
 *    present.
 * 2. **Stream-based check** — for chunked / streaming requests that omit
 *    Content-Length, the body is consumed in chunks and the running total
 *    is compared against the limit.  If within bounds the chunks are
 *    reassembled into a new Request so downstream `c.req.json()` still
 *    works.
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
      // Content-Length present and within bounds — skip stream check.
      await next();
      return;
    }

    // For methods that carry a body but lack Content-Length (chunked),
    // enforce the limit by reading the stream.
    if (!METHODS_WITH_BODY.has(c.req.method) || !c.req.raw.body) {
      await next();
      return;
    }

    const reader = c.req.raw.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        totalBytes += value.byteLength;
        if (totalBytes > maxSize) {
          await reader.cancel();
          throw new PayloadTooLargeError(
            `Request body exceeds maximum allowed size of ${maxSize} bytes`,
          );
        }
        chunks.push(value);
      }
    } catch (err) {
      if (err instanceof PayloadTooLargeError) throw err;
      throw new PayloadTooLargeError(
        `Request body exceeds maximum allowed size of ${maxSize} bytes`,
      );
    }

    // Reassemble the buffered body into a new Request so downstream
    // handlers can still call c.req.json() / c.req.text().
    const merged = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }

    const newRequest = new Request(c.req.raw.url, {
      method: c.req.raw.method,
      headers: c.req.raw.headers,
      body: merged,
    });
    Object.defineProperty(c.req, "raw", { value: newRequest, writable: true });

    await next();
  };
}
