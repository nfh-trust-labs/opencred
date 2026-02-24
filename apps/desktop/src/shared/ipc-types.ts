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
  /** Unique identifier for this key (internal). */
  id: string;
  /** Human-readable fingerprint (e.g. SHA-256 of the public key). */
  fingerprint: string;
  /** Key algorithm, e.g. "ECDSA P-256". */
  algorithm: string;
  /** When the key was imported (ISO 8601). */
  importedAt: string;
  /** Optional user-supplied label. */
  label?: string;
}

export interface KeyImportRequest {
  /** Absolute path to the key file on disk. */
  filePath: string;
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
  error?: string;
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

  // Signing & verification
  signCredential: (request: SignCredentialRequest) => Promise<SignCredentialResponse>;
  verifyCredential: (request: VerifyCredentialRequest) => Promise<VerifyCredentialResponse>;

  // File I/O
  openFile: (request: FileOpenRequest) => Promise<FileOpenResponse>;
  saveFile: (request: FileSaveRequest) => Promise<FileSaveResponse>;

  // Network status
  getOfflineStatus: () => Promise<boolean>;

  // Config
  getConfig: (key: string) => Promise<unknown>;
  setConfig: (key: string, value: unknown) => Promise<void>;
}
