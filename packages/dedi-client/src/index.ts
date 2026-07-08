// Primary — consumer-facing
export { DeDiClient } from "./adapter/client.js";
export { createDeDiDIDWebFallback } from "./adapter/did-web-fallback.js";
// Re-exported so callers (e.g. @opencred/verification) can branch on
// `err instanceof DeDiClientError && err.statusCode === 404` without
// reaching into @opencred/shared directly. The class itself is defined
// in shared/errors.ts.
export { DeDiClientError } from "@opencred/shared";
export type {
  DeDiClientConfig,
  RevocationHashRecord,
  KeyRecord,
  KeyStatus,
  SetKeyStatusResult,
  SchemaRecord,
  ContextRecord,
  PublishResult,
} from "./adapter/types.js";
export {
  REVOCATION_REGISTRY,
  OPENCRED_KEY_REGISTRY,
  SCHEMA_REGISTRY,
  CONTEXT_REGISTRY,
  verificationMethodToRecordName,
} from "./adapter/registry-names.js";

// Publishing orchestrator
export { DeDiPublishManager, createPublishManager } from "./publish-manager.js";

// Advanced — low-level API access
export { DeDiApiClient } from "./api/api-client.js";
export type { DeDiApiClientConfig } from "./api/api-client.js";
export { DeDiTokenManager } from "./api/auth.js";
export type { DeDiAuthConfig } from "./api/auth.js";
export type {
  DeDiNamespace,
  DeDiRegistry,
  DeDiRecord,
  DeDiResponse,
  DeDiProof,
  DeDiRegistrySummary,
  DeDiRecordSummary,
  DeDiQueryParams,
  DeDiQueryResult,
  DeDiSearchResult,
  DeDiJobStatus,
  DeDiWatchParams,
  DeDiWatchSubscription,
  DeDiStats,
  DeDiRecordState,
  DeDiRegistryState,
  DeDiNamespaceState,
  DeDiRegistryTag,
  DeDiAuthTokens,
} from "./api/types.js";

// Resilience
export { CircuitBreaker, CircuitBreakerState } from "./circuit-breaker.js";
export type { CircuitBreakerOptions } from "./circuit-breaker.js";
export { withRetry } from "./retry.js";
export type { RetryOptions } from "./retry.js";

// Logging
export type { DeDiLogger } from "./logger.js";
export { noopLogger } from "./logger.js";
