import { DeDiClientError } from "@opencred/shared";
import { CircuitBreaker } from "../circuit-breaker.js";
import type { DeDiLogger } from "../logger.js";
import { noopLogger } from "../logger.js";
import { withRetry } from "../retry.js";
import { DeDiTokenManager } from "./auth.js";
import type { DeDiAuthConfig } from "./auth.js";
import type {
  DeDiNamespace,
  DeDiRegistry,
  DeDiRegistryTag,
  DeDiRecord,
  DeDiRecordState,
  DeDiQueryParams,
  DeDiQueryResult,
  DeDiSearchResult,
  DeDiTxtRecord,
  DeDiVerificationStatus,
  DeDiJobStatus,
  DeDiWatchParams,
  DeDiWatchSubscription,
  DeDiStats,
} from "./types.js";

export interface DeDiApiClientConfig {
  baseUrl: string;
  timeoutMs: number;
  auth: DeDiAuthConfig["auth"];
  circuitBreakerThreshold: number;
  maxRetries: number;
  logger?: DeDiLogger;
}

export class DeDiApiClient {
  private readonly config: DeDiApiClientConfig;
  private readonly tokenManager: DeDiTokenManager;
  private readonly circuitBreaker: CircuitBreaker;
  private readonly logger: DeDiLogger;

  constructor(config: DeDiApiClientConfig) {
    if (config.timeoutMs <= 0) {
      throw new DeDiClientError("timeoutMs must be positive", 400);
    }
    if (config.maxRetries < 0) {
      throw new DeDiClientError("maxRetries must be non-negative", 400);
    }
    if (config.circuitBreakerThreshold <= 0) {
      throw new DeDiClientError("circuitBreakerThreshold must be positive", 400);
    }

    // Enforce HTTPS in production to prevent credentials transmitting in plaintext
    const url = new URL(config.baseUrl);
    if (url.protocol !== "https:" && process.env.NODE_ENV !== "development" && process.env.NODE_ENV !== "test") {
      throw new DeDiClientError(
        "DeDi baseUrl must use HTTPS in production",
        400,
      );
    }

    this.config = config;
    this.logger = config.logger ?? noopLogger;
    this.tokenManager = new DeDiTokenManager({
      baseUrl: config.baseUrl,
      auth: config.auth,
      logger: this.logger,
    });
    this.circuitBreaker = new CircuitBreaker({
      threshold: config.circuitBreakerThreshold,
      logger: this.logger,
    });
  }

  // ── Namespace ────────────────────────────────────────────────────

  async createNamespace(name: string, description: string): Promise<DeDiNamespace> {
    return this.request<DeDiNamespace>("/dedi/namespace", {
      method: "POST",
      body: JSON.stringify({ name, description }),
    });
  }

  async lookupNamespace(ns: string): Promise<DeDiNamespace> {
    return this.request<DeDiNamespace>(`/dedi/lookup/${enc(ns)}`);
  }

  // ── Registry ─────────────────────────────────────────────────────

  async createRegistry(
    ns: string,
    name: string,
    schema: unknown,
    tag?: DeDiRegistryTag,
  ): Promise<DeDiRegistry> {
    return this.request<DeDiRegistry>(`/dedi/namespace/${enc(ns)}/registry`, {
      method: "POST",
      body: JSON.stringify({ name, schema, ...(tag ? { tag } : {}) }),
    });
  }

  async lookupRegistry(ns: string, reg: string): Promise<DeDiRegistry> {
    return this.request<DeDiRegistry>(`/dedi/lookup/${enc(ns)}/${enc(reg)}`);
  }

  async revokeRegistry(ns: string, reg: string): Promise<void> {
    await this.requestVoid(`/dedi/namespace/${enc(ns)}/registry/${enc(reg)}`, {
      method: "DELETE",
    });
  }

  // ── Record CRUD ──────────────────────────────────────────────────

  async publishRecord<T = unknown>(
    ns: string,
    reg: string,
    name: string,
    details: T,
  ): Promise<DeDiRecord<T>> {
    return this.request<DeDiRecord<T>>(
      `/dedi/namespace/${enc(ns)}/registry/${enc(reg)}/record`,
      {
        method: "POST",
        body: JSON.stringify({ name, detail: details }),
      },
    );
  }

  async lookupRecord<T = unknown>(
    ns: string,
    reg: string,
    recordName: string,
  ): Promise<DeDiRecord<T>> {
    return this.request<DeDiRecord<T>>(
      `/dedi/lookup/${enc(ns)}/${enc(reg)}/${enc(recordName)}`,
    );
  }

  async revokeRecord(ns: string, reg: string, recordName: string): Promise<void> {
    await this.changeRecordState(ns, reg, recordName, "revoked");
  }

  async changeRecordState(
    ns: string,
    reg: string,
    recordName: string,
    state: DeDiRecordState,
  ): Promise<void> {
    await this.requestVoid(
      `/dedi/namespace/${enc(ns)}/registry/${enc(reg)}/record/${enc(recordName)}/state`,
      {
        method: "PUT",
        body: JSON.stringify({ state }),
      },
    );
  }

  // ── Query & Search ───────────────────────────────────────────────

  async queryRecords<T = unknown>(
    ns: string,
    reg: string,
    params?: DeDiQueryParams,
  ): Promise<DeDiQueryResult<T>> {
    const qs = params ? toQueryString(params as Record<string, unknown>) : "";
    return this.request<DeDiQueryResult<T>>(
      `/dedi/namespace/${enc(ns)}/registry/${enc(reg)}/records${qs}`,
    );
  }

  async search<T = unknown>(
    ns: string,
    params: Record<string, string>,
  ): Promise<DeDiSearchResult<T>> {
    const qs = toQueryString(params);
    return this.request<DeDiSearchResult<T>>(`/dedi/search/${enc(ns)}${qs}`);
  }

  // ── Domain verification ──────────────────────────────────────────

  async generateTxt(ns: string): Promise<DeDiTxtRecord> {
    return this.request<DeDiTxtRecord>(
      `/dedi/namespace/${enc(ns)}/verify/generate`,
      { method: "POST" },
    );
  }

  async verifyDomain(ns: string, domain: string): Promise<void> {
    await this.requestVoid(`/dedi/namespace/${enc(ns)}/verify`, {
      method: "POST",
      body: JSON.stringify({ domain }),
    });
  }

  async checkVerification(ns: string): Promise<DeDiVerificationStatus> {
    return this.request<DeDiVerificationStatus>(
      `/dedi/namespace/${enc(ns)}/verify/status`,
    );
  }

  // ── Verification ─────────────────────────────────────────────────

  async verifyRecordLookup(response: unknown): Promise<void> {
    await this.requestVoid("/dedi/verify", {
      method: "POST",
      body: JSON.stringify(response),
    });
  }

  // ── Delegation (DeDi user delegation) ────────────────────────────

  async addDelegate(ns: string, reg: string, email: string): Promise<void> {
    await this.requestVoid(
      `/dedi/namespace/${enc(ns)}/registry/${enc(reg)}/delegate`,
      {
        method: "POST",
        body: JSON.stringify({ email }),
      },
    );
  }

  async removeDelegate(ns: string, reg: string, email: string): Promise<void> {
    await this.requestVoid(
      `/dedi/namespace/${enc(ns)}/registry/${enc(reg)}/delegate/${encodeURIComponent(email)}`,
      { method: "DELETE" },
    );
  }

  // ── Bulk ─────────────────────────────────────────────────────────

  async bulkUpload(
    ns: string,
    reg: string,
    file: Blob,
  ): Promise<{ job_id: string }> {
    return this.circuitBreaker.execute(() =>
      withRetry(
        async () => {
          const formData = new FormData();
          formData.append("file", file);
          const token = await this.tokenManager.getToken();

          const url = `${this.config.baseUrl}/dedi/namespace/${enc(ns)}/registry/${enc(reg)}/bulk`;
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

          try {
            const response = await globalThis.fetch(url, {
              method: "POST",
              headers: { Authorization: `Bearer ${token}` },
              body: formData,
              signal: controller.signal,
            });

            if (!response.ok) {
              throw new DeDiClientError(
                `DeDi API error: ${response.status}`,
                response.status >= 500 ? 502 : response.status,
              );
            }

            return (await response.json()) as { job_id: string };
          } catch (error) {
            if (error instanceof DeDiClientError) throw error;
            if (error instanceof DOMException && error.name === "AbortError") {
              throw new DeDiClientError(
                `DeDi API request timed out after ${this.config.timeoutMs}ms`,
                504,
              );
            }
            throw new DeDiClientError(
              `DeDi API network error: ${error instanceof Error ? error.message : "unknown"}`,
              502,
            );
          } finally {
            clearTimeout(timeoutId);
          }
        },
        { maxRetries: this.config.maxRetries, logger: this.logger },
      ),
    );
  }

  async getJobStatus(jobId: string): Promise<DeDiJobStatus> {
    return this.request<DeDiJobStatus>(`/dedi/jobs/${enc(jobId)}`);
  }

  // ── Watch ────────────────────────────────────────────────────────

  async createWatch(params: DeDiWatchParams): Promise<DeDiWatchSubscription> {
    return this.request<DeDiWatchSubscription>("/dedi/watch", {
      method: "POST",
      body: JSON.stringify(params),
    });
  }

  async deleteWatch(subId: string): Promise<void> {
    await this.requestVoid(`/dedi/watch/${enc(subId)}`, { method: "DELETE" });
  }

  async listWatchSubscriptions(): Promise<DeDiWatchSubscription[]> {
    return this.request<DeDiWatchSubscription[]>("/dedi/watch");
  }

  // ── Stats (public) ──────────────────────────────────────────────

  async getStats(): Promise<DeDiStats> {
    return this.request<DeDiStats>("/dedi/stats");
  }

  // ── Internal HTTP plumbing ───────────────────────────────────────

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    return this.circuitBreaker.execute(() =>
      withRetry(() => this.fetchJson<T>(path, init), {
        maxRetries: this.config.maxRetries,
        logger: this.logger,
      }),
    );
  }

  private async requestVoid(path: string, init?: RequestInit): Promise<void> {
    await this.circuitBreaker.execute(() =>
      withRetry(() => this.fetchVoid(path, init), {
        maxRetries: this.config.maxRetries,
        logger: this.logger,
      }),
    );
  }

  private async fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.doFetch(path, init);

    if (!response.ok) {
      throw new DeDiClientError(
        `DeDi API error: ${response.status}`,
        response.status >= 500 ? 502 : response.status,
      );
    }

    try {
      return (await response.json()) as T;
    } catch {
      throw new DeDiClientError(`DeDi API returned non-JSON response`, 502);
    }
  }

  private async fetchVoid(path: string, init?: RequestInit): Promise<void> {
    const response = await this.doFetch(path, init);

    if (!response.ok) {
      throw new DeDiClientError(
        `DeDi API error: ${response.status}`,
        response.status >= 500 ? 502 : response.status,
      );
    }
  }

  private async doFetch(path: string, init?: RequestInit): Promise<Response> {
    const url = `${this.config.baseUrl}${path}`;
    const token = await this.tokenManager.getToken();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      return await globalThis.fetch(url, {
        ...init,
        signal: controller.signal,
        headers: {
          ...(init?.body ? { "Content-Type": "application/json" } : {}),
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          ...init?.headers,
        },
      });
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
        `DeDi API network error: ${error instanceof Error ? error.message : "unknown"}`,
        502,
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

function enc(value: string): string {
  return encodeURIComponent(value);
}

function toQueryString(params: Record<string, unknown>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== null,
  );
  if (entries.length === 0) return "";
  const qs = entries
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join("&");
  return `?${qs}`;
}
