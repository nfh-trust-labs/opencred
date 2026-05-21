// DeDi OpenAPI v2.0.0 component schemas
// These types model the real DeDi API's namespace → registry → record hierarchy.

// ── State enums ──────────────────────────────────────────────────────

export type DeDiRecordState = "draft" | "live" | "suspended" | "revoked" | "expired";

export type DeDiRegistryState = "active" | "archived" | "revoked";

export type DeDiNamespaceState = "active" | "archived" | "revoked";

// Tag values are case-sensitive record names from the dedi.global/schemas
// registry. Verified directly against api.dedi.global on 2026-05-21:
// "Revoke" / "Membership" / "Public_key" / "Public-Data-Set" / etc. are the
// exact strings the server accepts. Lowercase ("revoke", "membership") and
// the previously-assumed "custom" tag are rejected with
// `400 Invalid input: tag is not valid` — DeDi has no no-schema tag, so
// registries that store free-form payloads must pass an inline JSON schema.
export type DeDiRegistryTag =
  | "Membership"
  | "Public-Data-Set"
  | "Public_key"
  | "Revoke"
  | "beckn_subscriber"
  | "beckn_subscriber_reference";

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

// ── Envelope ─────────────────────────────────────────────────────────

/**
 * The standard DeDi response envelope. The real wire format wraps every
 * successful response in `{ message, data }` — see Postman `develop`
 * collection, 2026-05-19. `data` is the payload (single record, array
 * of records, job descriptor, etc.) and `message` is a human-readable
 * status string set by the server. This generic models the wrapper so
 * adapter code unwraps `data` explicitly rather than treating the
 * envelope as the payload.
 */
export interface DeDiResponse<T> {
  message: string;
  data: T;
}

// ── Record ───────────────────────────────────────────────────────────

/**
 * A single DeDi record as it appears under `response.data`. The HTTP
 * layer wraps this in `DeDiResponse<DeDiRecord<T>>` on lookup/publish
 * paths; adapters extract `response.data.details` to get the OpenCred
 * payload.
 *
 * Field names match the wire shape exactly (`record_name`, `details`
 * plural, `version` as a string, etc.) so JSON parsing is direct.
 */
export interface DeDiRecord<T = unknown> {
  record_name: string;
  registry: string;
  namespace: string;
  details: T;
  state: DeDiRecordState;
  /** Version is a string on the wire (e.g. `"1"`), not a number. */
  version: string;
  created_at: string;
  updated_at: string;
  /** CORD-blockchain anchor metadata. Present on most lookup responses. */
  proof?: DeDiProof;
  /** Optional TTL in seconds for this record. */
  ttl?: number;
  /** Optional ISO 8601 timestamp at which the record expires. */
  valid_till?: string;
}

/**
 * Proof block surfaced by DeDi alongside record responses. Anchors the
 * record to the underlying CORD blockchain so verifiers can independently
 * confirm the entry exists on-chain. Surfaced here as opaque metadata;
 * the verifier UI / downstream consumers may surface specific fields.
 */
export interface DeDiProof {
  /** Proof type, e.g. `"DediRecordProof2026"`. */
  type: string;
  /** DID of the namespace controller. */
  namespace_did: string;
  /** Registry-level identifier when the proof is registry-scoped. */
  registry_identifier?: string;
  /** Record-level identifier when the proof is record-scoped. */
  record_identifier?: string;
  /** DID of the entity that created the record. */
  creator_did: string;
  /** Hash of the record's contents as anchored on-chain. */
  digest: string;
  /** Genesis hash of the network this record was anchored against. */
  network_genesis: string | null;
}

export interface DeDiRecordSummary {
  record_name: string;
  state: DeDiRecordState;
  version: string;
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

/**
 * Query/search responses return their payload as a bare array under
 * `data` (i.e. `{ message, data: DeDiRecord<T>[] }`). Pagination, if
 * any, is communicated out-of-band; the response itself is the array.
 */
export type DeDiQueryResult<T = unknown> = DeDiRecord<T>[];

export type DeDiSearchResult<T = unknown> = DeDiRecord<T>[];

// ── Domain verification ──────────────────────────────────────────────

export interface DeDiTxtRecord {
  txt_record: string;
}

export interface DeDiVerificationStatus {
  verified: boolean;
}

// ── Bulk ─────────────────────────────────────────────────────────────

export type DeDiJobState = "pending" | "processing" | "completed" | "failed";

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
