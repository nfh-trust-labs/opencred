import { DeDiClientError } from "@opencred/shared";
import type { DeDiLogger } from "./logger.js";

export interface RetryOptions {
  maxRetries: number;
  baseDelayMs: number;
  logger?: DeDiLogger;
}

const DEFAULT_OPTIONS: RetryOptions = {
  maxRetries: 3,
  baseDelayMs: 200,
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
    return error.statusCode >= 500;
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
      const delay = opts.baseDelayMs * Math.pow(2, attempt);
      await sleep(delay);
    }
  }

  throw lastError;
}
