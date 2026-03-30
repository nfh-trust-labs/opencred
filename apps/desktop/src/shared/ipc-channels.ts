/**
 * IPC channel names for main <-> renderer communication.
 *
 * All IPC channels are defined here as typed constants so that both the main
 * process (ipc-handlers.ts) and the renderer preload (preload.ts) reference
 * the same channel strings. This prevents typo-related silent failures and
 * enables compile-time checking.
 */

export const IPC_CHANNELS = {
  // --- Key management ---
  /** Import a key file from disk. Payload: file path. Response: key metadata (id, fingerprint). */
  KEY_IMPORT: "key:import",
  /** List imported key identifiers. Response: array of key metadata. */
  KEY_LIST: "key:list",
  /** Generate a fresh ECDSA P-256 keypair in-app. Payload: optional label. Response: key metadata. */
  KEY_GENERATE: "key:generate",

  // --- Schema ---
  /** List all available schema IDs. Response: string array. */
  SCHEMA_LIST: "schema:list",
  /** Get a specific schema definition. Payload: schemaId. Response: schema definition. */
  SCHEMA_GET: "schema:get",

  // --- Signing ---
  /** Request the main process to sign a credential. Payload: unsigned VC + key ID. Response: signed VC. */
  SIGN_CREDENTIAL: "credential:sign",
  /** Build and sign a credential in one step. Payload: signing options + key ID. Response: signed VC + packaging. */
  BUILD_AND_SIGN: "credential:build-and-sign",

  // --- Verification ---
  /** Verify a signed credential. Payload: VC JSON string. Response: verification result. */
  VERIFY_CREDENTIAL: "credential:verify",

  // --- Packaging ---
  /** Package a signed VC into QR, PDF, JSON formats. Payload: VC + formats. Response: packaged outputs. */
  PACKAGE_CREDENTIAL: "credential:package",

  // --- Revocation ---
  /** Queue a credential revocation. Payload: credential ID + registry URL. Response: queue item. */
  REVOCATION_QUEUE: "revocation:queue",
  /** Get revocation queue status. Response: queue items array. */
  REVOCATION_STATUS: "revocation:status",
  /** Trigger publication of pending revocations. Response: publish results. */
  REVOCATION_PUBLISH: "revocation:publish",

  // --- File operations ---
  /** Open a native file-open dialog. Payload: dialog options. Response: file contents or null. */
  FILE_OPEN: "file:open",
  /** Open a native file-save dialog and write contents. Payload: { defaultName, content }. Response: saved path or null. */
  FILE_SAVE: "file:save",

  // --- Offline status ---
  /** Query the current online/offline status. Response: boolean. */
  GET_OFFLINE_STATUS: "status:offline",

  // --- Batch issuance ---
  /** Start batch processing with CSV data + config. Response: initial progress. */
  BATCH_START: "batch:start",
  /** Get current batch progress. Response: BatchProgress. */
  BATCH_STATUS: "batch:status",
  /** Cancel running batch. Response: void. */
  BATCH_CANCEL: "batch:cancel",
  /** Export batch results as ZIP. Payload: output path. Response: export result. */
  BATCH_EXPORT: "batch:export",

  // --- PKCS#11 hardware tokens ---
  /** Check if a PKCS#11 library exists at the given path. Payload: { libraryPath }. Response: { exists, error? }. */
  PKCS11_DETECT: "pkcs11:detect",
  /** List available PKCS#11 slots/tokens. Payload: { libraryPath }. Response: { slots }. */
  PKCS11_LIST_SLOTS: "pkcs11:list-slots",
  /** List keys on a specific token (after PIN entry). Payload: { libraryPath, slotIndex, pin }. Response: { keys }. */
  PKCS11_LIST_KEYS: "pkcs11:list-keys",
  /** Open session and select a key for signing. Payload: { libraryPath, slotIndex, pin, keyId?, label? }. Response: key metadata. */
  PKCS11_CONNECT: "pkcs11:connect",

  // --- Auto-update ---
  /** Manually check for updates. Response: UpdateStatusResponse. */
  UPDATE_CHECK: "update:check",
  /** Start downloading an available update. Response: UpdateStatusResponse. */
  UPDATE_DOWNLOAD: "update:download",
  /** Install downloaded update (quit and install). Response: void. */
  UPDATE_INSTALL: "update:install",
  /** Get current update status. Response: UpdateStatusResponse. */
  UPDATE_STATUS: "update:status",

  // --- OS certificate store ---
  /** List certificates from the OS certificate store. Response: certificate list with platform info. */
  OSCERT_LIST: "oscert:list",
  /** Sign data using an OS certificate's private key. Payload: { certificateId, data }. Response: signature. */
  OSCERT_SIGN: "oscert:sign",
  /** Select and connect an OS certificate for signing. Payload: { certificateId, label? }. Response: key metadata. */
  OSCERT_CONNECT: "oscert:connect",

  // --- Self-Published Keys (did:web) ---
  DID_WEB_EXPORT: "keys:export-did-document",
  DID_WEB_VERIFY: "keys:verify-did-web",

  // --- Recent templates ---
  /** List recently used templates. Response: RecentTemplatesListResponse. */
  RECENT_TEMPLATES_LIST: "recent-templates:list",
  /** Record a template usage. Payload: { schemaId, schemaName }. Response: void. */
  RECENT_TEMPLATES_RECORD: "recent-templates:record",

  // --- Credential history (deprecated) ---
  CREDENTIAL_HISTORY_LIST: "credential-history:list",
  CREDENTIAL_HISTORY_ADD: "credential-history:add",
  CREDENTIAL_HISTORY_DELETE: "credential-history:delete",

  // --- Schema URL fetch ---
  /** Fetch a JSON Schema from a URL. Payload: { url }. Response: { success, schema?, title?, error? }. */
  SCHEMA_FETCH_URL: "schema:fetch-url",

  // --- Custom schemas ---
  /** Save a custom schema. Payload: schema definition. Response: void. */
  CUSTOM_SCHEMA_SAVE: "custom-schema:save",
  /** List custom schemas. Response: schema array. */
  CUSTOM_SCHEMA_LIST: "custom-schema:list",
  /** Delete a custom schema. Payload: { id }. Response: void. */
  CUSTOM_SCHEMA_DELETE: "custom-schema:delete",

  // --- Config (electron-store) ---
  /** Read a config value. Payload: key string. Response: value or undefined. */
  GET_CONFIG: "config:get",
  /** Write a config value. Payload: { key, value }. Response: void. */
  SET_CONFIG: "config:set",

  // --- DeDi integration ---
  /** Save DeDi configuration. Payload: DeDiConfigSetRequest. Response: DeDiConfigSetResponse. */
  DEDI_SET_CONFIG: "dedi:set-config",
  /** Get DeDi integration status. Response: DeDiStatusResponse. */
  DEDI_GET_STATUS: "dedi:get-status",
  /** Publish a DID document to DeDi. Payload: DeDiPublishDIDRequest. Response: DeDiPublishResponse. */
  DEDI_PUBLISH_DID: "dedi:publish-did",
  /** Publish a schema to DeDi. Payload: DeDiPublishSchemaRequest. Response: DeDiPublishResponse. */
  DEDI_PUBLISH_SCHEMA: "dedi:publish-schema",
  /** Ensure DeDi registries exist. Response: DeDiEnsureRegistriesResponse. */
  DEDI_ENSURE_REGISTRIES: "dedi:ensure-registries",
  /** Disconnect DeDi integration (clear config + credentials). Response: DeDiDisconnectResponse. */
  DEDI_DISCONNECT: "dedi:disconnect",

  // --- System / diagnostics ---
  /** Get system info (app version, OS, paths). Response: SystemInfoResponse. */
  SYSTEM_INFO: "system:info",
  /** Read recent log lines from the log file. Response: LogTailResponse. */
  LOG_TAIL: "log:tail",
} as const;

/** Union type of all IPC channel name values. */
export type IpcChannel = (typeof IPC_CHANNELS)[keyof typeof IPC_CHANNELS];
