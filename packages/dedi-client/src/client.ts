import { DeDiClientError } from "@opencred/shared";
import { CircuitBreaker } from "./circuit-breaker.js";
import { withRetry } from "./retry.js";
import type {
  DeDiClientConfig,
  RevocationHashRecord,
  DelegationRecord,
  DIDRecord,
} from "./types.js";

export class DeDiClient {
  private readonly config: DeDiClientConfig;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(config: DeDiClientConfig) {
    this.config = config;
    this.circuitBreaker = new CircuitBreaker({
      threshold: config.circuitBreakerThreshold,
    });
  }

  async publishRevocationHash(hash: string): Promise<RevocationHashRecord> {
    return this.request<RevocationHashRecord>("/revocations", {
      method: "POST",
      body: JSON.stringify({ hash }),
    });
  }

  async queryRevocationHash(hash: string): Promise<RevocationHashRecord> {
    return this.request<RevocationHashRecord>(
      `/revocations/${encodeURIComponent(hash)}`,
    );
  }

  async resolveDID(did: string): Promise<DIDRecord> {
    return this.request<DIDRecord>(`/dids/${encodeURIComponent(did)}`);
  }

  async registerDelegation(delegation: unknown): Promise<DelegationRecord> {
    return this.request<DelegationRecord>("/delegations", {
      method: "POST",
      body: JSON.stringify(delegation),
    });
  }

  async resolveDelegation(delegationId: string): Promise<DelegationRecord> {
    return this.request<DelegationRecord>(
      `/delegations/${encodeURIComponent(delegationId)}`,
    );
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    return this.circuitBreaker.execute(() =>
      withRetry(
        () => this.fetch<T>(path, init),
        { maxRetries: this.config.maxRetries },
      ),
    );
  }

  private async fetch<T>(path: string, init?: RequestInit): Promise<T> {
    const url = `${this.config.baseUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      this.config.timeoutMs,
    );

    try {
      const response = await globalThis.fetch(url, {
        ...init,
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          ...init?.headers,
        },
      });

      if (!response.ok) {
        throw new DeDiClientError(
          `DeDi API error: ${response.status}`,
          response.status >= 500 ? 502 : response.status,
        );
      }

      return (await response.json()) as T;
    } catch (error) {
      if (error instanceof DeDiClientError) {
        throw error;
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new DeDiClientError(
          `DeDi API request timed out after ${this.config.timeoutMs}ms`,
          504,
        );
      }
      throw new DeDiClientError(
        "DeDi API network error",
        502,
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
