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
}

export interface KeyImportRequest {
  /** Absolute path to the key file on disk. */
  filePath: string;
  /** Optional user-friendly label for the key. */
  label?: string;
}

export interface KeyImportResponse {
  success: boolean;
  key?: KeyMetadata;
  error?: string;
}

export interface KeyListResponse {
  keys: KeyMetadata[];
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export interface SchemaListResponse {
  schemas: string[];
}

export interface SchemaGetRequest {
  schemaId: string;
}

export interface SchemaGetResponse {
  id: string;
  schema: Record<string, unknown>;
  contextUrl?: string;
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

export interface BuildAndSignRequest {
  /** The schema ID to validate against. */
  schemaId: string;
  /** The issuer DID. */
  issuerDid: string;
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
}

export interface BuildAndSignResponse {
  success: boolean;
  /** JSON-serialised signed Verifiable Credential. */
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
}

export interface FileSaveRequest {
  /** Suggested default file name. */
  defaultName: string;
  /** The content to write. */
  content: string;
  /** File type filters. */
  filters?: Array<{ name: string; extensions: string[] }>;
}

export interface FileSaveResponse {
  /** The path where the file was saved, or null if cancelled. */
  filePath: string | null;
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
// Preload API shape (exposed on window.opencred)
// ---------------------------------------------------------------------------

export interface OpenCredDesktopAPI {
  // Key management
  importKey: (request: KeyImportRequest) => Promise<KeyImportResponse>;
  listKeys: () => Promise<KeyListResponse>;

  // Schema
  listSchemas: () => Promise<SchemaListResponse>;
  getSchema: (request: SchemaGetRequest) => Promise<SchemaGetResponse>;

  // Signing & verification
  signCredential: (request: SignCredentialRequest) => Promise<SignCredentialResponse>;
  buildAndSign: (request: BuildAndSignRequest) => Promise<BuildAndSignResponse>;
  verifyCredential: (request: VerifyCredentialRequest) => Promise<VerifyCredentialResponse>;

  // Packaging
  packageCredential: (request: PackageCredentialRequest) => Promise<PackageCredentialResponse>;

  // Revocation
  queueRevocation: (request: RevocationQueueRequest) => Promise<RevocationQueueResponse>;
  getRevocationStatus: () => Promise<RevocationStatusResponse>;
  publishRevocations: () => Promise<RevocationPublishResponse>;

  // File I/O
  openFile: (request: FileOpenRequest) => Promise<FileOpenResponse>;
  saveFile: (request: FileSaveRequest) => Promise<FileSaveResponse>;

  // Network status
  getOfflineStatus: () => Promise<boolean>;

  // Config
  getConfig: (key: string) => Promise<unknown>;
  setConfig: (key: string, value: unknown) => Promise<void>;
}
