/**
 * Type definitions for IPC request and response payloads.
 *
 * SECURITY NOTE: Key material (private keys, signing buffers) MUST NEVER
 * appear in these types or be transmitted over IPC. Only key metadata
 * (id, fingerprint, algorithm) crosses the IPC boundary. The actual private
 * key stays in the main process and is never exposed to the renderer.
 */

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/** Metadata returned after importing a key — never contains the private key itself. */
export interface KeyMetadata {
  /** Unique identifier for this key (did:key verification method ID). */
  id: string;
  /** Human-readable fingerprint (e.g. SHA-256 of the public key). */
  fingerprint: string;
  /** Key algorithm, e.g. "ECDSA P-256". */
  algorithm: string;
  /** When the key was imported (ISO 8601). */
  importedAt: string;
  /** Optional user-supplied label. */
  label?: string;
  /** Detected key format (pem, jwk, pkcs8-der). */
  format?: string;
  /** How this key was loaded into the application. */
  source?: "file" | "pkcs11" | "os-cert" | "generated";
}

export interface KeyImportRequest {
  /** Absolute path to the key file on disk. */
  filePath: string;
  /** Optional user-friendly label for the key. */
  label?: string;
  /** Password for PFX/P12 files (ignored for PEM). */
  password?: string;
}

export interface KeyImportResponse {
  success: boolean;
  key?: KeyMetadata;
  error?: string;
}

export interface KeyListResponse {
  keys: KeyMetadata[];
}

export interface KeyGenerateRequest {
  /** Optional user-friendly label for the generated key. */
  label?: string;
}

export interface KeyGenerateResponse {
  success: boolean;
  key?: KeyMetadata;
  error?: string;
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export interface SchemaListEntry {
  id: string;
  category?: string;
}

export interface SchemaListResponse {
  schemas: SchemaListEntry[];
}

export interface SchemaGetRequest {
  schemaId: string;
}

export interface SchemaGetResponse {
  id: string;
  schema: Record<string, unknown>;
  contextUrl?: string;
}

export interface SchemaGenerateRequest {
  fields: Record<string, unknown>;
}

export interface SchemaGenerateResponse {
  schema: Record<string, unknown>;
  fields: Array<{ name: string; type: string; format?: string; required: boolean }>;
}

// ---------------------------------------------------------------------------
// Credential signing
// ---------------------------------------------------------------------------

export interface SignCredentialRequest {
  /** JSON-serialised unsigned Verifiable Credential. */
  unsignedCredential: string;
  /** ID of the key to use for signing (must have been imported). */
  keyId: string;
}

export interface SignCredentialResponse {
  success: boolean;
  /** JSON-serialised signed Verifiable Credential (if success). */
  signedCredential?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Build and Sign (full flow)
// ---------------------------------------------------------------------------

/** UI-facing proof format union (3 user-visible choices). */
export type UiProofFormat = "vc-jwt" | "data-integrity" | "sd-jwt-vc";

export interface BuildAndSignRequest {
  /** The schema ID to validate against. */
  schemaId: string;
  /** The issuer DID. */
  issuerDid: string;
  /** Inline JSON Schema for blank credentials (alternative to schemaId lookup). */
  inlineSchema?: Record<string, unknown>;
  /** Credential subject fields. */
  credentialSubject: Record<string, unknown>;
  /** ISO 8601 validFrom date. */
  validFrom: string;
  /** ISO 8601 validUntil date (optional). */
  validUntil?: string;
  /** Revocation registry URL (optional). */
  revocationRegistryUrl?: string;
  /** Additional credential types (optional). */
  additionalTypes?: string[];
  /** Subject DID (optional). */
  subjectDid?: string;
  /** ID of the key to use for signing. */
  keyId: string;
  /** Output packaging formats (optional). */
  packageFormats?: string[];
  /** Proof format (default: "vc-jwt"). */
  proofFormat?: UiProofFormat;
  /** Field names for SD-JWT-VC selective disclosure. */
  selectiveDisclosureClaims?: string[];
  /** Optional credential schema URL (JSON Schema link). */
  credentialSchemaUrl?: string;
  /** Context URL for custom schemas (e.g., DeDi-published context). */
  contextUrl?: string;
  /** Inline JSON-LD context for custom schemas (auto-generated). */
  inlineContext?: Record<string, unknown>;
}

export interface BuildAndSignResponse {
  success: boolean;
  /** JSON-serialised signed Verifiable Credential (or SD-JWT-VC compact string). */
  signedCredential?: string;
  /** Packaged outputs (if packaging was requested). */
  packagedOutputs?: Array<{
    format: string;
    /** Base64-encoded data for binary formats, string for text formats. */
    data: string;
    mimeType: string;
    suggestedFileName: string;
  }>;
  error?: string;
  /** Echo back proof format for display/export logic. */
  proofFormat?: string;
  /** Structured error code for contextual UI display. */
  errorCode?: string;
  /** Which field caused the error (for inline error display). */
  errorField?: string;
}

// ---------------------------------------------------------------------------
// Credential verification
// ---------------------------------------------------------------------------

export interface VerifyCredentialRequest {
  /** JSON-serialised Verifiable Credential to verify. */
  credential: string;
}

export interface VerifyCredentialResponse {
  success: boolean;
  /** Whether the credential is cryptographically valid. */
  valid?: boolean;
  /** Human-readable summary of verification. */
  message?: string;
  /** Detailed verification checks. */
  checks?: Array<{ name: string; passed: boolean; detail?: string }>;
  error?: string;
}

// ---------------------------------------------------------------------------
// Packaging
// ---------------------------------------------------------------------------

export interface PackageCredentialRequest {
  /** JSON-serialised signed Verifiable Credential. */
  credential: string;
  /** Output formats to produce. */
  formats: string[];
  /** Schema ID for template lookup (used by "svg" format). */
  schemaId?: string;
  /** Template customization options (used by "svg" and "pdf" formats). */
  customization?: {
    primaryColor?: string;
    logoDataUri?: string;
    issuerDisplayName?: string;
    backgroundColor?: string;
    secondaryColor?: string;
    textColor?: string;
    labelColor?: string;
    logoWidth?: number;
    logoHeight?: number;
    footerText?: string;
    sealDataUri?: string;
  };
}

export interface PackageCredentialResponse {
  success: boolean;
  outputs?: Array<{
    format: string;
    /** Base64-encoded data for binary formats, string for text formats. */
    data: string;
    mimeType: string;
    suggestedFileName: string;
  }>;
  errors?: Array<{ format: string; error: string }>;
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/**
 * Credentials the issuer provides to authenticate with a DeDi revocation registry.
 *
 * SECURITY NOTE: These are the issuer's own credentials — they are passed
 * ephemerally per publish request and NEVER persisted or logged.
 */
export type DeDiCredentials =
  | { type: "api-key"; apiKey: string }
  | { type: "bearer"; email: string; password: string };

export interface RevocationPublishRequest {
  /** Issuer's DeDi registry credentials. */
  dediCredentials: DeDiCredentials;
  /** Base URL of the DeDi revocation registry. */
  dediBaseUrl: string;
}

export interface RevocationQueueRequest {
  /** The credential ID to revoke. */
  credentialId: string;
  /** The revocation registry URL. */
  registryUrl: string;
  /** Optional revocation hash. */
  revocationHash?: string;
  /** Optional reason for revocation. */
  reason?: string;
}

export interface RevocationQueueResponse {
  success: boolean;
  item?: {
    queueId: string;
    credentialId: string;
    status: string;
    queuedAt: string;
  };
  error?: string;
}

export interface RevocationStatusResponse {
  items: Array<{
    queueId: string;
    credentialId: string;
    registryUrl: string;
    status: string;
    queuedAt: string;
    lastAttemptAt?: string;
    lastError?: string;
    attemptCount: number;
    reason?: string;
  }>;
}

export interface RevocationPublishResponse {
  results: Array<{
    queueId: string;
    success: boolean;
    error?: string;
  }>;
}

// ---------------------------------------------------------------------------
// File operations
// ---------------------------------------------------------------------------

export interface FileOpenRequest {
  /** Dialog title. */
  title?: string;
  /** File type filters (e.g. [{ name: "JSON", extensions: ["json"] }]). */
  filters?: Array<{ name: string; extensions: string[] }>;
}

export interface FileOpenResponse {
  /** null if the user cancelled. */
  content: string | null;
  /** The selected file path, or null if cancelled. */
  filePath: string | null;
  /** When set to "base64", content is base64-encoded binary data. */
  encoding?: "base64";
}

export interface FileSaveRequest {
  /** Suggested default file name. */
  defaultName: string;
  /** The content to write. */
  content: string;
  /** Content encoding — "base64" for binary files (PDF, PNG), defaults to "utf-8". */
  encoding?: "utf-8" | "base64";
  /** File type filters. */
  filters?: Array<{ name: string; extensions: string[] }>;
}

export interface FileSaveResponse {
  /** The path where the file was saved, or null if cancelled. */
  filePath: string | null;
  /** When set to "base64", content is base64-encoded binary data. */
  encoding?: "base64";
}

// ---------------------------------------------------------------------------
// Batch issuance
// ---------------------------------------------------------------------------

/** Column mapping: CSV column header -> schema property name. */
export interface BatchColumnMapping {
  [csvColumn: string]: string;
}

export interface BatchStartRequest {
  /** The raw CSV text content. */
  csvContent: string;
  /** The schema ID for all credentials. */
  schemaId: string;
  /** The issuer DID. */
  issuerDid: string;
  /** ISO 8601 validFrom date. */
  validFrom: string;
  /** ISO 8601 validUntil date (optional). */
  validUntil?: string;
  /** Revocation registry URL (optional). */
  revocationRegistryUrl?: string;
  /** Additional credential types (optional). */
  additionalTypes?: string[];
  /** Column-to-schema-field mapping. If not provided, headers are used as-is. */
  columnMapping?: BatchColumnMapping;
  /** ID of the signing key. */
  keyId: string;
  /** Output packaging formats. Defaults to ["json"]. */
  packageFormats?: string[];
  /** Force a specific delimiter instead of auto-detecting. */
  delimiter?: "," | ";" | "\t";
  /** Proof format (default: "vc-jwt"). */
  proofFormat?: UiProofFormat;
  /** Field names for SD-JWT-VC selective disclosure. */
  selectiveDisclosureClaims?: string[];
  /** Optional credential schema URL (JSON Schema link). */
  credentialSchemaUrl?: string;
}

/** Status of a single row in the batch. */
export type BatchRowStatus = "pending" | "processing" | "success" | "error" | "skipped";

/** Per-row result sent over IPC (credentials serialized as JSON strings). */
export interface BatchRowResultIpc {
  rowIndex: number;
  status: BatchRowStatus;
  error?: string;
  /** JSON-serialized signed credential (if success). */
  signedCredential?: string;
}

export interface BatchStartResponse {
  success: boolean;
  /** CSV headers detected from the file. */
  headers?: string[];
  /** Number of valid rows that will be processed. */
  validCount?: number;
  /** Number of invalid rows (skipped). */
  invalidCount?: number;
  /** Total row count. */
  totalCount?: number;
  /** Per-row parse validation results (before processing). */
  parseErrors?: Array<{ rowIndex: number; errors: Array<{ field: string; message: string }> }>;
  error?: string;
}

export interface BatchStatusResponse {
  /** Total rows. */
  total: number;
  /** Completed rows. */
  completed: number;
  /** Success count. */
  successCount: number;
  /** Error count. */
  errorCount: number;
  /** Skipped count (invalid rows or cancelled). */
  skippedCount: number;
  /** Whether the batch is currently running. */
  running: boolean;
  /** Whether the batch was cancelled. */
  cancelled: boolean;
  /** Per-row results. */
  rows: BatchRowResultIpc[];
}

export interface BatchCancelResponse {
  success: boolean;
}

export interface BatchExportRequest {
  /** Output file path for the ZIP. */
  outputPath: string;
}

export interface BatchExportResponse {
  success: boolean;
  /** Absolute path to the created ZIP file. */
  filePath?: string;
  /** Number of credentials exported. */
  credentialCount?: number;
  /** Total number of files in the ZIP. */
  fileCount?: number;
  error?: string;
}

// ---------------------------------------------------------------------------
// PKCS#11 hardware tokens
// ---------------------------------------------------------------------------

export interface Pkcs11DetectRequest {
  /** Absolute path to the PKCS#11 shared library. */
  libraryPath: string;
}

export interface Pkcs11DetectResponse {
  /** Whether the library file exists and appears valid. */
  exists: boolean;
  error?: string;
}

export interface Pkcs11ListSlotsRequest {
  /** Absolute path to the PKCS#11 shared library. */
  libraryPath: string;
}

export interface Pkcs11ListSlotsResponse {
  success: boolean;
  slots?: Array<{
    index: number;
    description: string;
    tokenPresent: boolean;
    tokenLabel?: string;
    tokenManufacturer?: string;
  }>;
  error?: string;
}

export interface Pkcs11ListKeysRequest {
  /** Absolute path to the PKCS#11 shared library. */
  libraryPath: string;
  /** Slot index. */
  slotIndex: number;
  /** Token PIN — entered by user, never stored. */
  pin: string;
}

export interface Pkcs11ListKeysResponse {
  success: boolean;
  keys?: Array<{
    /** CKA_LABEL of the key. */
    label: string;
    /** CKA_ID of the key (hex-encoded). */
    id: string;
    /** Key type (e.g., "EC"). */
    keyType: string;
    /** Whether the key has an associated public key. */
    hasPublicKey: boolean;
  }>;
  error?: string;
}

export interface Pkcs11ConnectRequest {
  /** Absolute path to the PKCS#11 shared library. */
  libraryPath: string;
  /** Slot index (default: 0). */
  slotIndex?: number;
  /** Token PIN — entered by user, never stored. */
  pin: string;
  /** Hex-encoded CKA_ID of the key (optional — uses first EC key if not set). */
  keyId?: string;
  /** Optional user-friendly label. */
  label?: string;
}

export interface Pkcs11ConnectResponse {
  success: boolean;
  /** Key metadata for the connected key. */
  key?: KeyMetadata;
  /** All available keys on the token. */
  availableKeys?: Array<{
    label: string;
    id: string;
    keyType: string;
    hasPublicKey: boolean;
  }>;
  error?: string;
}

// ---------------------------------------------------------------------------
// Auto-update
// ---------------------------------------------------------------------------

/** Progress information for an in-flight update download. */
export interface UpdateProgress {
  percent: number;
  bytesPerSecond: number;
  total: number;
  transferred: number;
}

/** Snapshot of the current auto-update state. */
export interface UpdateStatusResponse {
  checking: boolean;
  available: boolean;
  downloading: boolean;
  downloaded: boolean;
  version?: string;
  releaseNotes?: string;
  progress?: UpdateProgress;
  error?: string;
}

// ---------------------------------------------------------------------------
// OS certificate store
// ---------------------------------------------------------------------------

/** Info about a certificate in the OS certificate store. */
export interface OsCertInfoIpc {
  /** Platform-specific certificate identifier. */
  id: string;
  /** Certificate subject Common Name (CN). */
  subject: string;
  /** Certificate issuer Common Name (CN). */
  issuer: string;
  /** Certificate serial number (hex-encoded). */
  serialNumber: string;
  /** Certificate validity start (ISO 8601). */
  validFrom: string;
  /** Certificate validity end (ISO 8601). */
  validUntil: string;
  /** Key algorithm description (e.g., "ECDSA P-256"). */
  keyAlgorithm: string;
  /** Whether the private key is marked as exportable. */
  isExportable: boolean;
  /** SHA-256 thumbprint of the DER-encoded certificate (hex-encoded). */
  thumbprint: string;
}

export interface OsCertListResponse {
  success: boolean;
  /** Certificates found in the OS store. */
  certificates?: OsCertInfoIpc[];
  /** Runtime platform. */
  platform?: string;
  /** Human-readable store name (e.g., "macOS Keychain"). */
  storeName?: string;
  error?: string;
}

export interface OsCertSignRequest {
  /** Platform-specific certificate identifier. */
  certificateId: string;
  /** Base64-encoded data to sign. */
  data: string;
}

export interface OsCertSignResponse {
  success: boolean;
  /** Base64-encoded raw r||s signature (64 bytes). */
  signature?: string;
  error?: string;
}

export interface OsCertConnectRequest {
  /** Platform-specific certificate identifier. */
  certificateId: string;
  /** Optional user-friendly label. */
  label?: string;
}

export interface OsCertConnectResponse {
  success: boolean;
  /** Key metadata for the connected certificate. */
  key?: KeyMetadata;
  error?: string;
}

// ---------------------------------------------------------------------------
// Self-Published Keys (did:web)
// ---------------------------------------------------------------------------

export interface DidWebExportRequest {
  keyId: string;
  domain: string;
}

export interface DidWebExportResponse {
  success: boolean;
  didDocument?: string;
  did?: string;
  error?: string;
}

export interface DidWebVerifyRequest {
  domain: string;
}

export interface DidWebVerifyResponse {
  success: boolean;
  accessible: boolean;
  error?: string;
}

// ---------------------------------------------------------------------------
// DeDi integration
// ---------------------------------------------------------------------------

/**
 * Configuration for DeDi integration. Persisted in electron-store.
 *
 * SECURITY NOTE: DeDi credentials are the issuer's own API credentials for
 * their DeDi namespace. They are persisted encrypted in electron-store and
 * NEVER logged.
 */
export interface DeDiConfig {
  /** Base URL of the DeDi API (e.g., "https://api.dedi.global"). */
  baseUrl: string;
  /** The issuer's DeDi namespace (typically their domain). */
  namespace: string;
  /** Authentication credentials. */
  credentials: DeDiCredentials;
}

export interface DeDiConfigSetRequest {
  baseUrl: string;
  namespace: string;
  credentials: DeDiCredentials;
}

export interface DeDiConfigSetResponse {
  success: boolean;
  /** Whether registries were successfully created/verified. */
  registriesReady?: boolean;
  error?: string;
}

export interface DeDiStatusResponse {
  /** Whether DeDi integration is configured. */
  configured: boolean;
  /** The configured namespace (if any). */
  namespace?: string;
  /** Whether the 3 DeDi registries have been created. */
  registriesReady: boolean;
  /** Schema IDs that have been published to DeDi. */
  publishedSchemas: string[];
}

export interface DeDiPublishDIDRequest {
  /** The DID to publish. */
  did: string;
  /** The DID document (JSON). */
  document: unknown;
}

export interface DeDiPublishSchemaRequest {
  /** The schema ID to publish (from schema-engine registry). */
  schemaId: string;
}

export interface DeDiPublishResponse {
  success: boolean;
  recordName?: string;
  error?: string;
}

export interface DeDiEnsureRegistriesResponse {
  success: boolean;
  error?: string;
}

export interface DeDiDisconnectResponse {
  success: boolean;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface ConfigGetRequest {
  key: string;
}

export interface ConfigSetRequest {
  key: string;
  value: unknown;
}

// ---------------------------------------------------------------------------
// Recent templates
// ---------------------------------------------------------------------------

export interface RecentTemplatesListResponse {
  templates: Array<{
    schemaId: string;
    schemaName: string;
    lastUsedAt: string;
    useCount: number;
  }>;
}

export interface RecentTemplateRecordRequest {
  schemaId: string;
  schemaName: string;
}

// ---------------------------------------------------------------------------
// Credential history (deprecated — replaced by recent templates)
// ---------------------------------------------------------------------------

export interface CredentialHistoryAddRequest {
  schemaId: string;
  schemaName: string;
  subjectSummary: string;
  credentialJson: string;
  keyFingerprint: string;
  proofFormat?: string;
}

export interface CredentialHistoryListResponse {
  entries: Array<{
    id: string;
    schemaId: string;
    schemaName: string;
    subjectSummary: string;
    issuedAt: string;
    credentialJson: string;
    keyFingerprint: string;
    proofFormat?: string;
  }>;
}

export interface CredentialHistoryDeleteRequest {
  id: string;
}

export interface CredentialHistoryDeleteResponse {
  deleted: boolean;
}

// ---------------------------------------------------------------------------
// Schema URL fetch
// ---------------------------------------------------------------------------

export interface SchemaFetchUrlRequest {
  url: string;
}

export interface SchemaFetchUrlResponse {
  success: boolean;
  schema?: Record<string, unknown>;
  title?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Custom schemas
// ---------------------------------------------------------------------------

export interface CustomSchemaSaveRequest {
  name: string;
  schema: Record<string, unknown>;
  /** If provided, updates an existing custom schema; otherwise creates new. */
  id?: string;
  /** Source URL if the schema was imported from a URL. */
  sourceUrl?: string;
  /**
   * Optional user-provided JSON-LD context URL. If set, the main process will
   * fetch the context document at save time, validate it, and cache it locally
   * so the bundled JSON-LD loader can serve it during issuance/verification.
   */
  contextUrl?: string;
}

export interface CustomSchemaSaveResponse {
  id: string;
  name: string;
  schema: Record<string, unknown>;
  createdAt: string;
  sourceUrl?: string;
  /** Whether the save (and any context fetch) succeeded. */
  success?: boolean;
  /** The context URL that was fetched (if any). */
  contextUrl?: string;
  /** Whether a context document was successfully fetched and cached. */
  contextCached?: boolean;
  /** ISO 8601 timestamp at which the context was cached. */
  cachedContextFetchedAt?: string;
  /**
   * Error message if the context-fetch step failed. Note: even when this
   * is set, the schema itself was saved (the fetch error is non-fatal),
   * so the renderer can still treat the call as successful for the
   * purposes of displaying / re-using the schema.
   */
  error?: string;
}

export interface CustomSchemaListResponse {
  schemas: Array<{
    id: string;
    name: string;
    schema: Record<string, unknown>;
    createdAt: string;
    contextUrl?: string;
    cachedContextFetchedAt?: string;
  }>;
}

export interface CustomSchemaDeleteRequest {
  id: string;
}

export interface CustomSchemaDeleteResponse {
  deleted: boolean;
}

// ---------------------------------------------------------------------------
// System / diagnostics
// ---------------------------------------------------------------------------

export interface SystemInfoResponse {
  appVersion: string;
  electronVersion: string;
  nodeVersion: string;
  os: string;
  osVersion: string;
  arch: string;
  logPath: string;
}

export interface LogTailResponse {
  logs: string;
  logPath: string;
}

// ---------------------------------------------------------------------------
// Preload API shape (exposed on window.opencred)
// ---------------------------------------------------------------------------

export interface OpenCredDesktopAPI {
  // Key management
  importKey: (request: KeyImportRequest) => Promise<KeyImportResponse>;
  listKeys: () => Promise<KeyListResponse>;
  generateKey: (request: KeyGenerateRequest) => Promise<KeyGenerateResponse>;

  // Schema
  listSchemas: () => Promise<SchemaListResponse>;
  getSchema: (request: SchemaGetRequest) => Promise<SchemaGetResponse>;
  generateSchema: (request: SchemaGenerateRequest) => Promise<SchemaGenerateResponse>;

  // Signing & verification
  signCredential: (request: SignCredentialRequest) => Promise<SignCredentialResponse>;
  buildAndSign: (request: BuildAndSignRequest) => Promise<BuildAndSignResponse>;
  verifyCredential: (request: VerifyCredentialRequest) => Promise<VerifyCredentialResponse>;

  // Packaging
  packageCredential: (request: PackageCredentialRequest) => Promise<PackageCredentialResponse>;

  // Revocation
  queueRevocation: (request: RevocationQueueRequest) => Promise<RevocationQueueResponse>;
  getRevocationStatus: () => Promise<RevocationStatusResponse>;
  publishRevocations: (request: RevocationPublishRequest) => Promise<RevocationPublishResponse>;

  // Batch issuance
  batchStart: (request: BatchStartRequest) => Promise<BatchStartResponse>;
  batchStatus: () => Promise<BatchStatusResponse>;
  batchCancel: () => Promise<BatchCancelResponse>;
  batchExport: (request: BatchExportRequest) => Promise<BatchExportResponse>;

  // File I/O
  openFile: (request: FileOpenRequest) => Promise<FileOpenResponse>;
  saveFile: (request: FileSaveRequest) => Promise<FileSaveResponse>;

  // Network status
  getOfflineStatus: () => Promise<boolean>;

  // PKCS#11 hardware tokens
  pkcs11Detect: (request: Pkcs11DetectRequest) => Promise<Pkcs11DetectResponse>;
  pkcs11ListSlots: (request: Pkcs11ListSlotsRequest) => Promise<Pkcs11ListSlotsResponse>;
  pkcs11ListKeys: (request: Pkcs11ListKeysRequest) => Promise<Pkcs11ListKeysResponse>;
  pkcs11Connect: (request: Pkcs11ConnectRequest) => Promise<Pkcs11ConnectResponse>;

  // Auto-update
  updateCheck: () => Promise<UpdateStatusResponse>;
  updateDownload: () => Promise<UpdateStatusResponse>;
  updateInstall: () => Promise<void>;
  updateGetStatus: () => Promise<UpdateStatusResponse>;
  onUpdateStatus: (callback: (status: UpdateStatusResponse) => void) => () => void;

  // OS certificate store
  osCertList: () => Promise<OsCertListResponse>;
  osCertSign: (request: OsCertSignRequest) => Promise<OsCertSignResponse>;
  osCertConnect: (request: OsCertConnectRequest) => Promise<OsCertConnectResponse>;

  // Recent templates
  recentTemplatesList: () => Promise<RecentTemplatesListResponse>;
  recentTemplatesRecord: (request: RecentTemplateRecordRequest) => Promise<void>;

  // Credential history (deprecated)
  credentialHistoryList: () => Promise<CredentialHistoryListResponse>;
  credentialHistoryAdd: (
    request: CredentialHistoryAddRequest,
  ) => Promise<CredentialHistoryAddRequest & { id: string; issuedAt: string }>;
  credentialHistoryDelete: (
    request: CredentialHistoryDeleteRequest,
  ) => Promise<CredentialHistoryDeleteResponse>;

  // Schema URL fetch
  schemaFetchUrl: (request: SchemaFetchUrlRequest) => Promise<SchemaFetchUrlResponse>;

  // Custom schemas
  customSchemaList: () => Promise<CustomSchemaListResponse>;
  customSchemaSave: (request: CustomSchemaSaveRequest) => Promise<CustomSchemaSaveResponse>;
  customSchemaDelete: (request: CustomSchemaDeleteRequest) => Promise<CustomSchemaDeleteResponse>;

  // Config
  getConfig: (key: string) => Promise<unknown>;
  setConfig: (key: string, value: unknown) => Promise<void>;

  // Self-Published Keys (did:web)
  exportDidDocument: (request: DidWebExportRequest) => Promise<DidWebExportResponse>;
  verifyDidWeb: (request: DidWebVerifyRequest) => Promise<DidWebVerifyResponse>;

  // DeDi integration
  dediSetConfig: (request: DeDiConfigSetRequest) => Promise<DeDiConfigSetResponse>;
  dediGetStatus: () => Promise<DeDiStatusResponse>;
  dediPublishDID: (request: DeDiPublishDIDRequest) => Promise<DeDiPublishResponse>;
  dediPublishSchema: (request: DeDiPublishSchemaRequest) => Promise<DeDiPublishResponse>;
  dediEnsureRegistries: () => Promise<DeDiEnsureRegistriesResponse>;
  dediDisconnect: () => Promise<DeDiDisconnectResponse>;

  // System / diagnostics
  getSystemInfo: () => Promise<SystemInfoResponse>;
  getRecentLogs: (lines?: number) => Promise<LogTailResponse>;
}
