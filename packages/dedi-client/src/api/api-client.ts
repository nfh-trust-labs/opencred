import { promises as dns } from "node:dns";
import { isIP } from "node:net";
import { DeDiClientError, isPrivateIP } from "@opencred/shared";
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

/**
 * Hard cap on per-request timeout. CLAUDE.md invariant #7 mandates a
 * 10-second ceiling on any fetch that may reach an issuer-configured
 * host, so a misconfigured `timeoutMs` cannot be weaponised to hold
 * sockets open against internal services.
 */
const MAX_REQUEST_TIMEOUT_MS = 10_000;

/**
 * TTL for the per-hostname DNS SSRF cache (Anand's P2-03). `assertHostIsPublic`
 * used to fire live `resolve4`+`resolve6` lookups on every single request;
 * for an operator-configured DeDi host under sustained load that is two
 * lookups per request to the same hostname. The cache drops the per-request
 * DNS I/O while still running the `isPrivateIP` check on the cached
 * addresses — so an IP that was public at resolution time but is now private
 * is still rejected during the 30 s window. A conservative TTL keeps the
 * rebinding window small enough that any realistic DNS attack still fails
 * within seconds, while allowing the hot path to avoid a resolver round
 * trip.
 */
const DNS_CACHE_TTL_MS = 30_000;

interface DnsCacheEntry {
  addresses: string[];
  resolvedAt: number;
}

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
  private readonly effectiveTimeoutMs: number;
  // Per-hostname cache of resolved addresses. Protects against DNS
  // rebinding the same way the uncached path did (every request still
  // runs `isPrivateIP` on the cached addresses), but avoids two DNS
  // lookups per request for static operator-configured hostnames.
  private readonly dnsCache = new Map<string, DnsCacheEntry>();

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

    // Parse and validate the base URL up front. This is a synchronous
    // sanity check. The async DNS-based SSRF check happens at request
    // time in `doFetch`, because the DNS record for the configured
    // host can change between construction and the first request
    // (DNS rebinding).
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(config.baseUrl);
    } catch {
      throw new DeDiClientError("DeDi baseUrl is not a valid URL", 400);
    }

    // Enforce HTTPS unconditionally. The previous NODE_ENV bypass
    // was a footgun: anyone who could set environment variables on
    // the issuer machine could downgrade every DeDi request to
    // plaintext. Tests and development environments must use
    // `https://` URLs; they stub `globalThis.fetch` and DNS
    // resolution (see test helpers) so they never need plain HTTP.
    if (parsedUrl.protocol !== "https:") {
      throw new DeDiClientError("DeDi baseUrl must use HTTPS", 400);
    }

    // Synchronous SSRF check: if the hostname is already a literal
    // IP, reject it now if it falls in a private range. For DNS-
    // resolved hostnames, the check is repeated asynchronously on
    // every request against the freshly-resolved address.
    const hostname = stripIpv6Brackets(parsedUrl.hostname);
    if (isIP(hostname) !== 0 && isPrivateIP(hostname)) {
      throw new DeDiClientError(
        "DeDi baseUrl must not target a private, loopback, or link-local IP",
        400,
      );
    }

    this.config = config;
    this.effectiveTimeoutMs = Math.min(config.timeoutMs, MAX_REQUEST_TIMEOUT_MS);
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
    // Non-idempotent POST — disable retry. The DeDi server does not currently
    // accept an `Idempotency-Key` header, and blind retry on a transient 5xx
    // (or a network blip after the row was already written) silently creates
    // duplicate namespaces on the user's account. See issue #546.
    return this.request<DeDiNamespace>(
      "/dedi/create-namespace",
      {
        method: "POST",
        body: JSON.stringify({ name, description, meta: {} }),
      },
      { retryable: false },
    );
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
    // Non-idempotent POST — disable retry. Same rationale as createNamespace:
    // duplicate registries on transient 5xx are easy to create and hard to
    // clean up. See issue #546.
    return this.request<DeDiRegistry>(
      `/dedi/${enc(ns)}/create-registry`,
      {
        method: "POST",
        body: JSON.stringify({
          registry_name: name,
          description: `OpenCred ${name} registry`,
          // DeDi API: either schema OR tag, not both
          ...(tag
            ? { tag }
            : {
                schema:
                  Object.keys(schema as Record<string, unknown>).length > 0
                    ? schema
                    : {
                        $schema: "http://json-schema.org/draft-07/schema#",
                        type: "object",
                        properties: {},
                      },
              }),
          meta: {},
        }),
      },
      { retryable: false },
    );
  }

  async lookupRegistry(ns: string, reg: string): Promise<DeDiRegistry> {
    return this.request<DeDiRegistry>(`/dedi/lookup/${enc(ns)}/${enc(reg)}`);
  }

  async revokeRegistry(ns: string, reg: string): Promise<void> {
    await this.requestVoid(`/dedi/${enc(ns)}/${enc(reg)}/revoke-registry`, {
      method: "POST",
    });
  }

  // ── Record CRUD ──────────────────────────────────────────────────

  async publishRecord<T = unknown>(
    ns: string,
    reg: string,
    name: string,
    details: T,
  ): Promise<DeDiRecord<T>> {
    // Step 1: Save record as draft and publish immediately
    const record = await this.request<DeDiRecord<T>>(
      `/dedi/${enc(ns)}/${enc(reg)}/save-record-as-draft?publish=true`,
      {
        method: "POST",
        body: JSON.stringify({
          record_name: name,
          description: `OpenCred record: ${name}`,
          details,
          meta: {},
        }),
      },
    );
    return record;
  }

  async lookupRecord<T = unknown>(
    ns: string,
    reg: string,
    recordName: string,
  ): Promise<DeDiRecord<T>> {
    return this.request<DeDiRecord<T>>(`/dedi/lookup/${enc(ns)}/${enc(reg)}/${enc(recordName)}`);
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
    // Map state to DeDi endpoint
    const action =
      state === "revoked"
        ? "revoke-record"
        : state === "suspended"
          ? "suspend-record"
          : state === "live"
            ? "reinstate-record"
            : null;
    if (!action) return;
    await this.requestVoid(`/dedi/${enc(ns)}/${enc(reg)}/${enc(recordName)}/${action}`, {
      method: "POST",
    });
  }

  // ── Query & Search ───────────────────────────────────────────────

  async queryRecords<T = unknown>(
    ns: string,
    reg: string,
    params?: DeDiQueryParams,
  ): Promise<DeDiQueryResult<T>> {
    const qs = params ? toQueryString(params as Record<string, unknown>) : "";
    return this.request<DeDiQueryResult<T>>(`/dedi/query/${enc(ns)}/${enc(reg)}${qs}`);
  }

  async search<T = unknown>(
    ns: string,
    params: Record<string, string>,
  ): Promise<DeDiSearchResult<T>> {
    const qs = toQueryString(params);
    return this.request<DeDiSearchResult<T>>(`/dedi/search/${enc(ns)}${qs}`);
  }

  // ── Domain verification ──────────────────────────────────────────

  async generateTxt(ns: string, domain: string): Promise<DeDiTxtRecord> {
    return this.request<DeDiTxtRecord>(`/dedi/generate-dns-txt/${enc(ns)}/${enc(domain)}`);
  }

  async verifyDomain(ns: string): Promise<void> {
    await this.requestVoid(`/dedi/verify-domain`, {
      method: "POST",
      body: JSON.stringify({ namespace_id: ns }),
    });
  }

  async checkVerification(ns: string): Promise<DeDiVerificationStatus> {
    return this.request<DeDiVerificationStatus>(`/dedi/check-verification/${enc(ns)}`);
  }

  // ── Verification ─────────────────────────────────────────────────

  async verifyRecordLookup(response: unknown): Promise<void> {
    await this.requestVoid("/dedi/verify-record-lookup", {
      method: "POST",
      body: JSON.stringify({ record_lookup_response: response }),
    });
  }

  // ── Delegation (DeDi user delegation) ────────────────────────────

  async addDelegate(ns: string, reg: string, email: string): Promise<void> {
    await this.requestVoid(`/dedi/${enc(ns)}/${enc(reg)}/add-delegate`, {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }

  async removeDelegate(ns: string, reg: string, email: string): Promise<void> {
    await this.requestVoid(`/dedi/${enc(ns)}/${enc(reg)}/remove-registry-delegate`, {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }

  // ── Bulk ─────────────────────────────────────────────────────────

  async bulkUpload(_ns: string, _reg: string, file: Blob): Promise<{ job_id: string }> {
    // Anand's P2-08: this method used to inline a copy of the entire
    // `doFetch` pipeline — AbortController, timeout, SSRF re-check,
    // logging, error handling — purely because the body is `FormData`
    // rather than a JSON string. Every bugfix to the shared fetch path
    // therefore had to be applied twice. `doFetch` now recognises
    // FormData bodies and skips the JSON `Content-Type` auto-set, so
    // we route through the shared pipeline. FormData is rebuilt per
    // retry attempt so the underlying blob can be re-read from scratch.
    return this.circuitBreaker.execute(() =>
      withRetry(
        async () => {
          const formData = new FormData();
          formData.append("file", file);
          const response = await this.doFetch("/dedi/bulk-upload", {
            method: "POST",
            body: formData,
          });
          if (!response.ok) {
            let errBody = "";
            try {
              errBody = await response.text();
            } catch {
              /* ignore */
            }
            this.logger.error(`DeDi API ${response.status} /dedi/bulk-upload`, {
              body: errBody.slice(0, 500),
            });
            throw new DeDiClientError(
              `DeDi API error: ${response.status}`,
              response.status >= 500 ? 502 : response.status,
            );
          }
          let parsed: unknown;
          try {
            parsed = await response.json();
          } catch {
            throw new DeDiClientError("DeDi API returned non-JSON response", 502);
          }
          assertBulkUploadResultShape(parsed);
          return parsed;
        },
        { maxRetries: this.config.maxRetries, logger: this.logger },
      ),
    );
  }

  async getJobStatus(jobId: string): Promise<DeDiJobStatus> {
    return this.request<DeDiJobStatus>(`/dedi/bulk-upload/status/${enc(jobId)}`);
  }

  // ── Watch ────────────────────────────────────────────────────────

  async createWatch(params: DeDiWatchParams): Promise<DeDiWatchSubscription> {
    return this.request<DeDiWatchSubscription>("/dedi/subscribe", {
      method: "POST",
      body: JSON.stringify(params),
    });
  }

  async deleteWatch(subId: string): Promise<void> {
    await this.requestVoid("/dedi/unsubscribe", {
      method: "POST",
      body: JSON.stringify({ id: subId }),
    });
  }

  async listWatchSubscriptions(): Promise<DeDiWatchSubscription[]> {
    return this.request<DeDiWatchSubscription[]>("/dedi/subscriptions");
  }

  // ── Stats (public) ──────────────────────────────────────────────

  async getStats(): Promise<DeDiStats> {
    return this.request<DeDiStats>("/dedi/stats");
  }

  // ── Internal HTTP plumbing ───────────────────────────────────────

  /**
   * Per-call request options that the public methods can use to override
   * the default retry/circuit-breaker behaviour.
   */
  private async request<T>(
    path: string,
    init?: RequestInit,
    callOptions?: { retryable?: boolean },
  ): Promise<T> {
    return this.circuitBreaker.execute(() =>
      withRetry(() => this.fetchJson<T>(path, init), {
        maxRetries: this.config.maxRetries,
        logger: this.logger,
        retryable: callOptions?.retryable,
      }),
    );
  }

  private async requestVoid(
    path: string,
    init?: RequestInit,
    callOptions?: { retryable?: boolean },
  ): Promise<void> {
    await this.circuitBreaker.execute(() =>
      withRetry(() => this.fetchVoid(path, init), {
        maxRetries: this.config.maxRetries,
        logger: this.logger,
        retryable: callOptions?.retryable,
      }),
    );
  }

  private async fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.doFetch(path, init);

    if (!response.ok) {
      const { text, json } = await readErrorBody(response);
      this.logger.error(`DeDi API ${response.status} ${path}`, { body: text.slice(0, 500) });
      throw new DeDiClientError(
        `DeDi API error: ${response.status}`,
        response.status >= 500 ? 502 : response.status,
        json ?? (text ? text : undefined),
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
      const { text, json } = await readErrorBody(response);
      this.logger.error(`DeDi API ${response.status} ${path}`, { body: text.slice(0, 500) });
      throw new DeDiClientError(
        `DeDi API error: ${response.status}`,
        response.status >= 500 ? 502 : response.status,
        json ?? (text ? text : undefined),
      );
    }
  }

  private async doFetch(path: string, init?: RequestInit): Promise<Response> {
    const method = init?.method ?? "GET";
    const url = `${this.config.baseUrl}${path}`;
    // SSRF re-check on every request — see `bulkUpload` for rationale.
    await this.assertHostIsPublic(url);
    const token = await this.tokenManager.getToken();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.effectiveTimeoutMs);

    this.logger.info(`DeDi request`, { method, path });
    const start = Date.now();

    try {
      // FormData bodies must not set `Content-Type`: the Fetch runtime
      // fills in the multipart boundary itself. Every other body type
      // (JSON strings, typed-array bodies) pre-P2-08 got the JSON
      // header by default and still does. See Anand's P2-08.
      const isFormData = typeof FormData !== "undefined" && init?.body instanceof FormData;
      const response = await globalThis.fetch(url, {
        ...init,
        signal: controller.signal,
        redirect: "error",
        headers: {
          ...(init?.body && !isFormData ? { "Content-Type": "application/json" } : {}),
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          ...init?.headers,
        },
      });
      this.logger.info(`DeDi response`, {
        method,
        path,
        status: response.status,
        durationMs: Date.now() - start,
      });
      return response;
    } catch (error) {
      const durationMs = Date.now() - start;
      if (error instanceof DeDiClientError) {
        this.logger.error(`DeDi request failed`, {
          method,
          path,
          durationMs,
          error: error.message,
        });
        throw error;
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        this.logger.error(`DeDi request timed out`, { method, path, durationMs });
        throw new DeDiClientError(
          `DeDi API request timed out after ${this.effectiveTimeoutMs}ms`,
          504,
        );
      }
      this.logger.error(`DeDi network error`, {
        method,
        path,
        durationMs,
        error: error instanceof Error ? error.message : "unknown",
      });
      throw new DeDiClientError(
        `DeDi API network error: ${error instanceof Error ? error.message : "unknown"}`,
        502,
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * SSRF guard: resolve the hostname of the fully-qualified request
   * URL and refuse to proceed if any returned address is private,
   * loopback, or link-local. Run on every request (not just at
   * construction) so that DNS rebinding between calls cannot sneak
   * traffic into internal networks.
   */
  private async assertHostIsPublic(requestUrl: string): Promise<void> {
    let parsed: URL;
    try {
      parsed = new URL(requestUrl);
    } catch {
      throw new DeDiClientError("DeDi request URL is malformed", 400);
    }

    const hostname = stripIpv6Brackets(parsed.hostname);

    // Literal IP — no DNS lookup, check directly.
    if (isIP(hostname) !== 0) {
      if (isPrivateIP(hostname)) {
        throw new DeDiClientError(
          "DeDi baseUrl must not target a private, loopback, or link-local IP",
          400,
        );
      }
      return;
    }

    // Hostname — resolve both A and AAAA records and require every
    // returned IP to be public. A single private record is enough
    // to reject the request. Reuse a 30s cache to avoid hitting the
    // resolver twice per request for the same operator-configured
    // hostname. The `isPrivateIP` check still runs on every request
    // against the cached addresses — the cache only eliminates the
    // DNS I/O, not the SSRF decision.
    const cached = this.dnsCache.get(hostname);
    let addresses: string[];
    if (cached && Date.now() - cached.resolvedAt < DNS_CACHE_TTL_MS) {
      addresses = cached.addresses;
    } else {
      const [v4Result, v6Result] = await Promise.allSettled([
        dns.resolve4(hostname),
        dns.resolve6(hostname),
      ]);
      addresses = [
        ...(v4Result.status === "fulfilled" ? v4Result.value : []),
        ...(v6Result.status === "fulfilled" ? v6Result.value : []),
      ];

      if (addresses.length === 0) {
        throw new DeDiClientError(`DeDi host did not resolve: ${hostname}`, 502);
      }

      this.dnsCache.set(hostname, { addresses, resolvedAt: Date.now() });
    }

    for (const ip of addresses) {
      if (isPrivateIP(ip)) {
        throw new DeDiClientError(
          "DeDi baseUrl must not target a private, loopback, or link-local IP",
          400,
        );
      }
    }
  }
}

/**
 * IPv6 hostnames parsed by `URL` retain their surrounding brackets
 * in `url.hostname`. `isIP`/`isPrivateIP` expect bare addresses.
 */
function stripIpv6Brackets(hostname: string): string {
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return hostname.slice(1, -1);
  }
  return hostname;
}

function enc(value: string): string {
  return encodeURIComponent(value);
}

/**
 * Read a non-2xx Response body once and return both the raw text and a
 * best-effort JSON parse. Errors are logged with the raw text (truncated)
 * and the JSON body is surfaced on `DeDiClientError.responseBody` so
 * adapters can branch on server-specific body codes (e.g.
 * `{ code: "NAMESPACE_EXISTS" }`).
 */
async function readErrorBody(
  response: Response,
): Promise<{ text: string; json: unknown | undefined }> {
  let text = "";
  try {
    text = await response.text();
  } catch {
    /* ignore — body already consumed or stream broken */
  }
  if (!text) return { text: "", json: undefined };
  try {
    return { text, json: JSON.parse(text) };
  } catch {
    return { text, json: undefined };
  }
}

function assertBulkUploadResultShape(value: unknown): asserts value is { job_id: string } {
  if (value == null || typeof value !== "object") {
    throw new DeDiClientError("DeDi API bulk upload response is missing or not an object", 502);
  }
  const rec = value as Record<string, unknown>;
  if (typeof rec["job_id"] !== "string") {
    throw new DeDiClientError("DeDi API bulk upload response missing required field: job_id", 502);
  }
}

function toQueryString(params: Record<string, unknown>): string {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== null);
  if (entries.length === 0) return "";
  const qs = entries
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join("&");
  return `?${qs}`;
}
