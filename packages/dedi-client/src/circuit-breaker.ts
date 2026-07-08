import { DeDiClientError } from "@opencred/shared";
import type { DeDiLogger } from "./logger.js";
import { noopLogger } from "./logger.js";

export enum CircuitBreakerState {
  CLOSED = "CLOSED",
  OPEN = "OPEN",
  HALF_OPEN = "HALF_OPEN",
}

export interface CircuitBreakerOptions {
  threshold: number;
  resetTimeoutMs: number;
  logger: DeDiLogger;
  /** When true, persistent 401/403 errors also count towards the failure threshold. */
  countAuthFailures: boolean;
}

const DEFAULT_OPTIONS: CircuitBreakerOptions = {
  threshold: 5,
  resetTimeoutMs: 30_000,
  logger: noopLogger,
  countAuthFailures: false,
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
        this.options.logger.debug("Circuit breaker transitioning from OPEN to HALF_OPEN");
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
      if (error instanceof DeDiClientError && error.statusCode < 500) {
        // Count persistent 401/403 as failures when configured, since
        // e.g. an expired API key will fail indefinitely without tripping the breaker.
        if (
          this.options.countAuthFailures &&
          (error.statusCode === 401 || error.statusCode === 403)
        ) {
          this.onFailure();
        }
        throw error;
      }
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    if (this.state === CircuitBreakerState.HALF_OPEN) {
      this.options.logger.debug("Circuit breaker transitioning from HALF_OPEN to CLOSED");
    }
    this.failureCount = 0;
    this.state = CircuitBreakerState.CLOSED;
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    if (this.state === CircuitBreakerState.HALF_OPEN) {
      this.options.logger.warn("Circuit breaker opened after HALF_OPEN failure");
      this.state = CircuitBreakerState.OPEN;
    } else if (this.failureCount >= this.options.threshold) {
      this.options.logger.warn(`Circuit breaker opened after ${this.failureCount} failures`);
      this.state = CircuitBreakerState.OPEN;
    }
  }
}
