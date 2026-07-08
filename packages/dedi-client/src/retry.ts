import { DeDiClientError } from "@opencred/shared";
import type { DeDiLogger } from "./logger.js";

export interface RetryOptions {
  maxRetries: number;
  baseDelayMs: number;
  logger?: DeDiLogger;
  /**
   * When `false`, the retry loop is short-circuited: the underlying `fn`
   * runs at most once and any error propagates immediately. Use this for
   * non-idempotent operations (POST creates without an `Idempotency-Key`)
   * where blind retry can produce duplicate rows on the server.
   *
   * Defaults to `true` to preserve historical behaviour for GETs and
   * other idempotent calls.
   */
  retryable?: boolean;
}

const DEFAULT_OPTIONS: RetryOptions = {
  maxRetries: 3,
  baseDelayMs: 200,
  retryable: true,
};

const TRANSIENT_NETWORK_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EPIPE",
  "EHOSTUNREACH",
  "ENETUNREACH",
]);

function hasTransientNetworkCode(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const code = (error as { code?: string }).code;
  if (code && TRANSIENT_NETWORK_CODES.has(code)) return true;
  const cause = (error as { cause?: unknown }).cause;
  if (cause) return hasTransientNetworkCode(cause);
  return false;
}

function isTransientError(error: unknown): boolean {
  if (error instanceof DeDiClientError) {
    // 5xx upstream failures and 429 rate limits are transient. 429 delays
    // honour the server's `Retry-After` when present — see the delay
    // computation in `withRetry`.
    return error.statusCode >= 500 || error.statusCode === 429;
  }
  if (error instanceof TypeError && error.message.includes("fetch")) {
    return true;
  }
  if (error instanceof DOMException && error.name === "AbortError") {
    return true;
  }
  if (hasTransientNetworkCode(error)) {
    return true;
  }
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  options?: Partial<RetryOptions>,
): Promise<T> {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  // Non-idempotent path — run once and surface the first error. Skipping
  // the retry loop entirely is what protects POST creates without an
  // `Idempotency-Key` from creating duplicate rows when a single user
  // click sees a transient upstream blip.
  if (opts.retryable === false) {
    return fn();
  }

  let lastError: unknown;

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt >= opts.maxRetries || !isTransientError(error)) {
        if (attempt >= opts.maxRetries && opts.maxRetries > 0) {
          opts.logger?.error(`All ${opts.maxRetries} retry attempts exhausted`);
        }
        throw error;
      }
      opts.logger?.debug(`Retrying request, attempt ${attempt + 1} of ${opts.maxRetries}`);
      // A server-provided `Retry-After` (429, issue #679) wins over the
      // exponential formula — deterministic (no jitter; the server already
      // picked the moment), capped at 10s so a hostile or buggy header
      // can't stall the caller. Otherwise: exponential backoff with
      // subtractive jitter (0.75–1.0×) to de-synchronise replicas retrying
      // the same outage — never exceeds the deterministic
      // baseDelayMs * 2^attempt upper bound per attempt.
      const retryAfterMs =
        error instanceof DeDiClientError && error.retryAfterMs !== undefined
          ? Math.min(error.retryAfterMs, 10_000)
          : undefined;
      const jitter = 0.75 + Math.random() * 0.25;
      const delay = retryAfterMs ?? Math.round(opts.baseDelayMs * Math.pow(2, attempt) * jitter);
      await sleep(delay);
    }
  }

  throw lastError;
}
