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
    const fn = vi
      .fn()
      .mockRejectedValue(new DeDiClientError("not found", 404));

    await expect(
      withRetry(fn, { maxRetries: 3, baseDelayMs: 100 }),
    ).rejects.toThrow("not found");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry on 400 errors", async () => {
    const fn = vi
      .fn()
      .mockRejectedValue(new DeDiClientError("bad request", 400));

    await expect(
      withRetry(fn, { maxRetries: 3, baseDelayMs: 100 }),
    ).rejects.toThrow("bad request");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries on network errors (non-DeDiClientError)", async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new TypeError("fetch failed"))
      .mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100 });
    await vi.advanceTimersByTimeAsync(100);
    const result = await promise;

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });
});
