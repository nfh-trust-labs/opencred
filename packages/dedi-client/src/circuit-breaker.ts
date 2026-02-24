import { DeDiClientError } from "@opencred/shared";
import { CircuitBreakerState } from "./types.js";

export interface CircuitBreakerOptions {
  threshold: number;
  resetTimeoutMs: number;
}

const DEFAULT_OPTIONS: CircuitBreakerOptions = {
  threshold: 5,
  resetTimeoutMs: 30_000,
};

export class CircuitBreaker {
  private state: CircuitBreakerState = CircuitBreakerState.CLOSED;
  private failureCount = 0;
  private lastFailureTime = 0;
  private readonly options: CircuitBreakerOptions;

  constructor(options?: Partial<CircuitBreakerOptions>) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }

  getState(): CircuitBreakerState {
    return this.state;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === CircuitBreakerState.OPEN) {
      if (Date.now() - this.lastFailureTime >= this.options.resetTimeoutMs) {
        this.state = CircuitBreakerState.HALF_OPEN;
      } else {
        throw new DeDiClientError("Circuit breaker is open — request rejected", 503);
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failureCount = 0;
    this.state = CircuitBreakerState.CLOSED;
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    if (
      this.state === CircuitBreakerState.HALF_OPEN ||
      this.failureCount >= this.options.threshold
    ) {
      this.state = CircuitBreakerState.OPEN;
    }
  }
}
