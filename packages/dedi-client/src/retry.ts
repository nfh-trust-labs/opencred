import { DeDiClientError } from "@opencred/shared";

export interface RetryOptions {
  maxRetries: number;
  baseDelayMs: number;
}

const DEFAULT_OPTIONS: RetryOptions = {
  maxRetries: 3,
  baseDelayMs: 200,
};

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
        throw error;
      }
      const delay = opts.baseDelayMs * Math.pow(2, attempt);
      await sleep(delay);
    }
  }

  throw lastError;
}
