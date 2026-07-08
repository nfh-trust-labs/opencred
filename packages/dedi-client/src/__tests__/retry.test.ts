import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DeDiClientError } from "@opencred/shared";
import { withRetry } from "../retry.js";

describe("withRetry", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("succeeds on first try without retrying", async () => {
    const fn = vi.fn().mockResolvedValue("ok");
    const result = await withRetry(fn, { maxRetries: 3 });
    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries on transient failure and succeeds eventually", async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new DeDiClientError("server error", 502))
      .mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
    await vi.advanceTimersByTimeAsync(100);
    const result = await promise;

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("gives up after max retries", async () => {
    const error = new DeDiClientError("server error", 502);
    const fn = vi.fn().mockImplementation(async () => {
      throw error;
    });

    const promise = withRetry(fn, { maxRetries: 2, baseDelayMs: 100 });

    // Attach rejection handler BEFORE advancing timers to avoid unhandled rejection
    const assertion = expect(promise).rejects.toThrow("server error");

    // Advance past all retry delays (100ms + 200ms)
    await vi.advanceTimersByTimeAsync(300);

    await assertion;
    expect(fn).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it("uses exponential backoff", async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new DeDiClientError("error", 500))
      .mockRejectedValueOnce(new DeDiClientError("error", 500))
      .mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });

    // First retry: 100ms * 2^0 = 100ms
    expect(fn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(100);
    expect(fn).toHaveBeenCalledTimes(2);

    // Second retry: 100ms * 2^1 = 200ms
    await vi.advanceTimersByTimeAsync(200);
    const result = await promise;

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("does NOT retry on 4xx errors", async () => {
    const fn = vi.fn().mockRejectedValue(new DeDiClientError("not found", 404));

    await expect(withRetry(fn, { maxRetries: 3, baseDelayMs: 100 })).rejects.toThrow("not found");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry on 400 errors", async () => {
    const fn = vi.fn().mockRejectedValue(new DeDiClientError("bad request", 400));

    await expect(withRetry(fn, { maxRetries: 3, baseDelayMs: 100 })).rejects.toThrow("bad request");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries on 429 rate-limit errors", async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new DeDiClientError("rate limited", 429))
      .mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
    await vi.advanceTimersByTimeAsync(100);
    const result = await promise;

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("exhausts retries on persistent 429 and surfaces the error", async () => {
    const fn = vi.fn().mockRejectedValue(new DeDiClientError("rate limited", 429));

    const promise = withRetry(fn, { maxRetries: 2, baseDelayMs: 100 });
    const assertion = expect(promise).rejects.toThrow("rate limited");
    await vi.advanceTimersByTimeAsync(300);
    await assertion;
    expect(fn).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it("retries on network errors (TypeError with fetch)", async () => {
    const fn = vi.fn().mockRejectedValueOnce(new TypeError("fetch failed")).mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
    await vi.advanceTimersByTimeAsync(100);
    const result = await promise;

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("does NOT retry on SyntaxError", async () => {
    const fn = vi.fn().mockRejectedValue(new SyntaxError("Unexpected token"));

    await expect(withRetry(fn, { maxRetries: 3, baseDelayMs: 100 })).rejects.toThrow(
      "Unexpected token",
    );
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry on TypeError without fetch message", async () => {
    const fn = vi.fn().mockRejectedValue(new TypeError("Cannot read properties of undefined"));

    await expect(withRetry(fn, { maxRetries: 3, baseDelayMs: 100 })).rejects.toThrow(
      "Cannot read properties of undefined",
    );
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry on generic Error", async () => {
    const fn = vi.fn().mockRejectedValue(new Error("something broke"));

    await expect(withRetry(fn, { maxRetries: 3, baseDelayMs: 100 })).rejects.toThrow(
      "something broke",
    );
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries on ECONNREFUSED network error", async () => {
    const err = Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
    const fn = vi.fn().mockRejectedValueOnce(err).mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
    await vi.advanceTimersByTimeAsync(100);
    const result = await promise;

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("retries on ETIMEDOUT network error", async () => {
    const err = Object.assign(new Error("connect ETIMEDOUT"), { code: "ETIMEDOUT" });
    const fn = vi.fn().mockRejectedValueOnce(err).mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
    await vi.advanceTimersByTimeAsync(100);
    const result = await promise;

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("retries on ECONNRESET network error", async () => {
    const err = Object.assign(new Error("read ECONNRESET"), { code: "ECONNRESET" });
    const fn = vi.fn().mockRejectedValueOnce(err).mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
    await vi.advanceTimersByTimeAsync(100);
    const result = await promise;

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("retries on error with transient cause code", async () => {
    const cause = Object.assign(new Error("inner"), { code: "ENOTFOUND" });
    const err = new TypeError("fetch failed");
    (err as unknown as { cause: Error }).cause = cause;
    const fn = vi.fn().mockRejectedValueOnce(err).mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
    await vi.advanceTimersByTimeAsync(100);
    const result = await promise;

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("does NOT retry on validation error (DeDiClientError 422)", async () => {
    const fn = vi.fn().mockRejectedValue(new DeDiClientError("validation failed", 422));

    await expect(withRetry(fn, { maxRetries: 3, baseDelayMs: 100 })).rejects.toThrow(
      "validation failed",
    );
    expect(fn).toHaveBeenCalledTimes(1);
  });

  describe("Retry-After on 429 (issue #679)", () => {
    it("retries a 429 and waits the Retry-After duration instead of the exponential delay", async () => {
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new DeDiClientError("rate limited", 429, undefined, 3000))
        .mockResolvedValue("ok");

      const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
      expect(fn).toHaveBeenCalledTimes(1);

      // Exponential would be 100ms; the server said 3000ms. No jitter — the
      // Retry-After path is deterministic.
      await vi.advanceTimersByTimeAsync(2999);
      expect(fn).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1);
      const result = await promise;

      expect(result).toBe("ok");
      expect(fn).toHaveBeenCalledTimes(2);
    });

    it("caps the Retry-After delay at 10s", async () => {
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new DeDiClientError("rate limited", 429, undefined, 60_000))
        .mockResolvedValue("ok");

      const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
      await vi.advanceTimersByTimeAsync(10_000);
      const result = await promise;

      expect(result).toBe("ok");
      expect(fn).toHaveBeenCalledTimes(2);
    });

    it("retries a 429 without Retry-After using the exponential formula", async () => {
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new DeDiClientError("rate limited", 429))
        .mockResolvedValue("ok");

      const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
      await vi.advanceTimersByTimeAsync(100);
      const result = await promise;

      expect(result).toBe("ok");
      expect(fn).toHaveBeenCalledTimes(2);
    });
  });

  describe("retryable: false (issue #546)", () => {
    it("does NOT retry a 5xx when retryable is false", async () => {
      // 500 would normally be retried (it's a transient error), but the
      // explicit retryable:false flag short-circuits the loop. This is
      // the protection against non-idempotent POSTs creating duplicates
      // on transient upstream failures.
      const fn = vi.fn().mockRejectedValue(new DeDiClientError("upstream blip", 502));

      await expect(
        withRetry(fn, { maxRetries: 3, baseDelayMs: 100, retryable: false }),
      ).rejects.toThrow("upstream blip");
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it("does NOT retry a network error when retryable is false", async () => {
      const fn = vi.fn().mockRejectedValue(new TypeError("fetch failed"));

      await expect(
        withRetry(fn, { maxRetries: 3, baseDelayMs: 100, retryable: false }),
      ).rejects.toThrow("fetch failed");
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it("still returns the result on success with retryable false", async () => {
      const fn = vi.fn().mockResolvedValue("ok");

      const result = await withRetry(fn, {
        maxRetries: 3,
        baseDelayMs: 100,
        retryable: false,
      });

      expect(result).toBe("ok");
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it("defaults to retryable true (preserves historical behaviour)", async () => {
      // Sanity check that omitting the flag retries like before.
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new DeDiClientError("upstream blip", 502))
        .mockResolvedValueOnce("ok");

      const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
      await vi.advanceTimersByTimeAsync(100);
      const result = await promise;

      expect(result).toBe("ok");
      expect(fn).toHaveBeenCalledTimes(2);
    });
  });
});
