import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DeDiClientError } from "@opencred/shared";
import { CircuitBreaker } from "../circuit-breaker.js";
import { CircuitBreakerState } from "../types.js";

describe("CircuitBreaker", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("starts in CLOSED state", () => {
    const cb = new CircuitBreaker();
    expect(cb.getState()).toBe(CircuitBreakerState.CLOSED);
  });

  it("stays CLOSED on successful calls", async () => {
    const cb = new CircuitBreaker({ threshold: 3 });
    const result = await cb.execute(() => Promise.resolve("ok"));
    expect(result).toBe("ok");
    expect(cb.getState()).toBe(CircuitBreakerState.CLOSED);
  });

  it("transitions CLOSED → OPEN after threshold failures", async () => {
    const cb = new CircuitBreaker({ threshold: 3 });

    for (let i = 0; i < 3; i++) {
      await expect(
        cb.execute(() => Promise.reject(new Error("fail"))),
      ).rejects.toThrow("fail");
    }

    expect(cb.getState()).toBe(CircuitBreakerState.OPEN);
  });

  it("rejects immediately when OPEN", async () => {
    const cb = new CircuitBreaker({ threshold: 1 });

    await expect(
      cb.execute(() => Promise.reject(new Error("fail"))),
    ).rejects.toThrow("fail");
    expect(cb.getState()).toBe(CircuitBreakerState.OPEN);

    await expect(
      cb.execute(() => Promise.resolve("ok")),
    ).rejects.toThrow(DeDiClientError);
    await expect(
      cb.execute(() => Promise.resolve("ok")),
    ).rejects.toThrow("Circuit breaker is open");
  });

  it("transitions OPEN → HALF_OPEN after reset timeout", async () => {
    const cb = new CircuitBreaker({ threshold: 1, resetTimeoutMs: 5000 });

    await expect(
      cb.execute(() => Promise.reject(new Error("fail"))),
    ).rejects.toThrow();
    expect(cb.getState()).toBe(CircuitBreakerState.OPEN);

    vi.advanceTimersByTime(5000);

    const result = await cb.execute(() => Promise.resolve("recovered"));
    expect(result).toBe("recovered");
    expect(cb.getState()).toBe(CircuitBreakerState.CLOSED);
  });

  it("transitions HALF_OPEN → CLOSED on success", async () => {
    const cb = new CircuitBreaker({ threshold: 1, resetTimeoutMs: 1000 });

    await expect(
      cb.execute(() => Promise.reject(new Error("fail"))),
    ).rejects.toThrow();

    vi.advanceTimersByTime(1000);

    const result = await cb.execute(() => Promise.resolve("ok"));
    expect(result).toBe("ok");
    expect(cb.getState()).toBe(CircuitBreakerState.CLOSED);
  });

  it("transitions HALF_OPEN → OPEN on failure", async () => {
    const cb = new CircuitBreaker({ threshold: 2, resetTimeoutMs: 1000 });

    // Trigger OPEN state
    for (let i = 0; i < 2; i++) {
      await expect(
        cb.execute(() => Promise.reject(new Error("fail"))),
      ).rejects.toThrow();
    }
    expect(cb.getState()).toBe(CircuitBreakerState.OPEN);

    vi.advanceTimersByTime(1000);

    // This should trigger HALF_OPEN, then failure should send it back to OPEN
    await expect(
      cb.execute(() => Promise.reject(new Error("still failing"))),
    ).rejects.toThrow("still failing");
    expect(cb.getState()).toBe(CircuitBreakerState.OPEN);
  });

  it("resets failure count on success", async () => {
    const cb = new CircuitBreaker({ threshold: 3 });

    // Two failures, then a success
    await expect(
      cb.execute(() => Promise.reject(new Error("fail"))),
    ).rejects.toThrow();
    await expect(
      cb.execute(() => Promise.reject(new Error("fail"))),
    ).rejects.toThrow();
    await cb.execute(() => Promise.resolve("ok"));

    // Two more failures should not open circuit (count was reset)
    await expect(
      cb.execute(() => Promise.reject(new Error("fail"))),
    ).rejects.toThrow();
    await expect(
      cb.execute(() => Promise.reject(new Error("fail"))),
    ).rejects.toThrow();
    expect(cb.getState()).toBe(CircuitBreakerState.CLOSED);
  });
});
