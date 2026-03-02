// DeDi OpenAPI v2.0.0 component schemas
// These types model the real DeDi API's namespace → registry → record hierarchy.

// ── State enums ──────────────────────────────────────────────────────

export type DeDiRecordState =
  | "draft"
  | "live"
  | "suspended"
  | "revoked"
  | "expired";

export type DeDiRegistryState = "active" | "archived" | "revoked";

export type DeDiNamespaceState = "active" | "archived" | "revoked";

export type DeDiRegistryTag = "custom" | "membership" | "public_key" | "revoke";

// ── Auth ─────────────────────────────────────────────────────────────

export interface DeDiAuthCredentials {
  email: string;
  password: string;
  action: "login" | "register";
}

export interface DeDiAuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
}

export interface DeDiApiKeyResponse {
  api_key: string;
  created_at: string;
}

// ── Namespace ────────────────────────────────────────────────────────

export interface DeDiNamespace {
  name: string;
  description: string;
  state: DeDiNamespaceState;
  verified: boolean;
  created_at: string;
  updated_at: string;
}

// ── Registry ─────────────────────────────────────────────────────────

export interface DeDiRegistry {
  name: string;
  namespace: string;
  schema: unknown;
  tag: DeDiRegistryTag;
  state: DeDiRegistryState;
  record_count: number;
  created_at: string;
  updated_at: string;
}

export interface DeDiRegistrySummary {
  name: string;
  tag: DeDiRegistryTag;
  state: DeDiRegistryState;
  record_count: number;
}

// ── Record ───────────────────────────────────────────────────────────

export interface DeDiRecord<T = unknown> {
  name: string;
  registry: string;
  namespace: string;
  detail: T;
  state: DeDiRecordState;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface DeDiRecordSummary {
  name: string;
  state: DeDiRecordState;
  version: number;
  updated_at: string;
}

// ── Query / Search ───────────────────────────────────────────────────

export interface DeDiQueryParams {
  page?: number;
  per_page?: number;
  state?: DeDiRecordState;
  sort?: "created_at" | "updated_at" | "name";
  order?: "asc" | "desc";
}

export interface DeDiQueryResult<T = unknown> {
  records: DeDiRecord<T>[];
  total: number;
  page: number;
  per_page: number;
}

export interface DeDiSearchResult<T = unknown> {
  records: DeDiRecord<T>[];
  total: number;
}

// ── Domain verification ──────────────────────────────────────────────

export interface DeDiTxtRecord {
  txt_record: string;
}

export interface DeDiVerificationStatus {
  verified: boolean;
}

// ── Bulk ─────────────────────────────────────────────────────────────

export type DeDiJobState =
  | "pending"
  | "processing"
  | "completed"
  | "failed";

export interface DeDiJobStatus {
  job_id: string;
  state: DeDiJobState;
  total: number;
  processed: number;
  failed: number;
  errors: string[];
  created_at: string;
  updated_at: string;
}

// ── Watch / Webhooks ─────────────────────────────────────────────────

export interface DeDiWatchParams {
  namespace: string;
  registry?: string;
  record?: string;
  callback_url: string;
  events: string[];
}

export interface DeDiWatchSubscription {
  subscription_id: string;
  namespace: string;
  registry?: string;
  record?: string;
  callback_url: string;
  events: string[];
  created_at: string;
}

// ── Stats ────────────────────────────────────────────────────────────

export interface DeDiStats {
  namespaces: number;
  registries: number;
  records: number;
}

// ── API response wrappers ────────────────────────────────────────────

export interface DeDiSuccessResponse<T> {
  data: T;
}

export interface DeDiErrorResponse {
  error: {
    code: string;
    message: string;
  };
}
