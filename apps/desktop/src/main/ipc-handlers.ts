/**
 * IPC handler registration for the Electron main process.
 *
 * Each handler corresponds to an IPC channel defined in ../shared/ipc-channels.ts.
 * The preload script (preload.ts) exposes these channels to the renderer via
 * contextBridge so that the renderer never has direct access to Node.js APIs.
 *
 * SECURITY INVARIANTS:
 *  - Private keys are NEVER sent to the renderer. Only key metadata (id,
 *    fingerprint, algorithm) is returned over IPC.
 *  - Key material is NEVER logged. Use key ID / fingerprint in diagnostics.
 *  - All crypto operations happen in the main process.
 */

import { ipcMain, dialog, type IpcMainInvokeEvent } from "electron";
import * as fs from "node:fs/promises";
import { IPC_CHANNELS } from "../shared/ipc-channels.js";
import type {
  KeyImportRequest,
  KeyImportResponse,
  KeyGenerateRequest,
  KeyGenerateResponse,
  KeyListResponse,
  KeyMetadata,
  SchemaListResponse,
  SchemaGetRequest,
  SchemaGetResponse,
  SignCredentialRequest,
  SignCredentialResponse,
  BuildAndSignRequest,
  BuildAndSignResponse,
  VerifyCredentialRequest,
  VerifyCredentialResponse,
  PackageCredentialRequest,
  PackageCredentialResponse,
  RevocationQueueRequest,
  RevocationQueueResponse,
  RevocationStatusResponse,
  RevocationPublishResponse,
  BatchStartRequest,
  BatchStartResponse,
  BatchStatusResponse,
  BatchCancelResponse,
  BatchExportRequest,
  BatchExportResponse,
  FileOpenRequest,
  FileOpenResponse,
  FileSaveRequest,
  FileSaveResponse,
  ConfigGetRequest,
  ConfigSetRequest,
  Pkcs11DetectRequest,
  Pkcs11DetectResponse,
  Pkcs11ListSlotsRequest,
  Pkcs11ListSlotsResponse,
  Pkcs11ListKeysRequest,
  Pkcs11ListKeysResponse,
  Pkcs11ConnectRequest,
  Pkcs11ConnectResponse,
  UpdateStatusResponse,
  OsCertListResponse,
  OsCertSignRequest,
  OsCertSignResponse,
  OsCertConnectRequest,
  OsCertConnectResponse,
} from "../shared/ipc-types.js";
import { getStore, restrictStoreFilePermissions } from "./store.js";
import { createSoftwareSigner, buildSigner } from "../signing/software-signer.js";
import { buildAndSign, listSchemas, getSchemaDefinition } from "../signing/local-signing-flow.js";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import { verifyProof } from "@opencred/crypto";
import { packageCredential } from "../packaging/packager.js";
import type { PackageFormat } from "../packaging/packager.js";
import { parseCredentialJson } from "../packaging/json-export.js";
import { queueRevocation, getQueueItems, publishPendingRevocations } from "./revocation-queue.js";
import type { Signer } from "../signing/types.js";
import { parseCsv } from "../batch/csv-parser.js";
import type { CsvParseResult, Delimiter } from "../batch/csv-parser.js";
import { createBatchEngine } from "../batch/batch-engine.js";
import type { BatchEngine, BatchRowResult } from "../batch/batch-engine.js";
import { exportBatchAsZip } from "../batch/batch-export.js";
// PKCS#11 imports are lazy to avoid requiring the native pkcs11.node addon at startup.
// The actual imports happen inside the handler functions via dynamic import().

import {
  checkForUpdates,
  downloadUpdate,
  quitAndInstall,
  getUpdateStatus,
} from "./auto-updater.js";
// OS cert imports are lazy to avoid requiring the native addon at startup.


// ---------------------------------------------------------------------------
// In-memory registries
// ---------------------------------------------------------------------------

/** Maps key ID (did:key VM ID) -> key metadata for display. */
const importedKeys = new Map<string, KeyMetadata>();

/** Maps key ID -> Signer instance (private key stays in memory, never serialized). */
const loadedSigners = new Map<string, Signer>();

/** Mutable batch processing state. */
const batchState: {
  engine: BatchEngine | null;
  results: BatchRowResult[] | null;
  parseResult: CsvParseResult | null;
} = {
  engine: null,
  results: null,
  parseResult: null,
};

// ---------------------------------------------------------------------------
// Key management handlers
// ---------------------------------------------------------------------------

/**
 * KEY_IMPORT — import a key file from disk.
 *
 * Reads the file, creates a SoftwareSigner (which validates P-256 and
 * extracts metadata), stores the signer in memory, and returns metadata.
 * The private key content is NEVER returned or logged.
 */
async function handleKeyImport(
  _event: IpcMainInvokeEvent,
  request: KeyImportRequest,
): Promise<KeyImportResponse> {
  try {
    const { signer, format } = createSoftwareSigner(request.filePath, request.label);

    const meta: KeyMetadata = {
      id: signer.id,
      fingerprint: signer.metadata.fingerprint,
      algorithm: "ECDSA P-256",
      importedAt: new Date().toISOString(),
      label: request.label,
      format,
      source: "file",
    };

    importedKeys.set(signer.id, meta);
    loadedSigners.set(signer.id, signer);

    // SECURITY TRADE-OFF: Persisting file paths enables auto-reload on
    // restart but means an attacker with filesystem read access can discover
    // file locations. The config file is restricted to owner-only permissions
    // (0600) to mitigate this. Users can opt out by setting persistKeyPaths
    // to false in the application settings.
    const store = getStore();
    const shouldPersist = store.get("persistKeyPaths" as keyof typeof store.store) ?? true;

    if (shouldPersist) {
      const prefs =
        (store.get("preferences" as keyof typeof store.store) as Record<string, unknown>) ?? {};
      const savedPaths = (prefs["importedKeyPaths"] as Record<string, string>) ?? {};
      savedPaths[signer.id] = request.filePath;
      store.set("preferences" as keyof typeof store.store, {
        ...prefs,
        importedKeyPaths: savedPaths,
      });

      // Restrict config file to owner-only read/write (0600) after writing.
      // On Windows this is a no-op; see store.ts for details.
      restrictStoreFilePermissions();
    }

    return { success: true, key: meta };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to import key.";
    return { success: false, error: message };
  }
}

/** KEY_LIST — return metadata for all imported keys. */
async function handleKeyList(): Promise<KeyListResponse> {
  return { keys: Array.from(importedKeys.values()) };
}

/**
 * KEY_GENERATE — generate a fresh ECDSA P-256 keypair in-app.
 *
 * Uses Node.js crypto to generate a keypair, delegates to buildSigner
 * for did:key derivation and Signer construction, then registers in
 * memory. The private key stays in-process and is NEVER returned or logged.
 */
async function handleKeyGenerate(
  _event: IpcMainInvokeEvent,
  request: KeyGenerateRequest,
): Promise<KeyGenerateResponse> {
  try {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const publicKey = createPublicKey(privateKey);
    const signer = buildSigner(privateKey, publicKey, request.label);

    const meta: KeyMetadata = {
      id: signer.id,
      fingerprint: signer.metadata.fingerprint,
      algorithm: "ECDSA P-256",
      importedAt: new Date().toISOString(),
      label: request.label,
      format: "generated",
      source: "generated",
    };

    importedKeys.set(signer.id, meta);
    loadedSigners.set(signer.id, signer);

    return { success: true, key: meta };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Key generation failed.";
    return { success: false, error: message };
  }
}

// ---------------------------------------------------------------------------
// Schema handlers
// ---------------------------------------------------------------------------

/** SCHEMA_LIST — list all available schema IDs. */
async function handleSchemaList(): Promise<SchemaListResponse> {
  return { schemas: listSchemas() };
}

/** SCHEMA_GET — get a specific schema definition. */
async function handleSchemaGet(
  _event: IpcMainInvokeEvent,
  request: SchemaGetRequest,
): Promise<SchemaGetResponse> {
  const definition = getSchemaDefinition(request.schemaId);
  return {
    id: definition.id,
    schema: definition.schema,
    contextUrl: definition.contextUrl,
  };
}

// ---------------------------------------------------------------------------
// Signing handlers
// ---------------------------------------------------------------------------

/**
 * SIGN_CREDENTIAL — sign an unsigned VC with the specified key.
 *
 * Uses the local signing flow: prepareProof -> sign -> completeProof.
 */
async function handleSignCredential(
  _event: IpcMainInvokeEvent,
  request: SignCredentialRequest,
): Promise<SignCredentialResponse> {
  const signer = loadedSigners.get(request.keyId);
  if (!signer) {
    return { success: false, error: `Key not found: ${request.keyId}` };
  }

  try {
    const { prepareProof, completeProof } = await import("@opencred/crypto");
    const unsignedCredential = JSON.parse(request.unsignedCredential);

    const { dataToSign, proofConfig } = await prepareProof(unsignedCredential, {
      verificationMethod: signer.id,
      proofPurpose: "assertionMethod",
    });

    const signatureBytes = await signer.sign(dataToSign);
    const signedCredential = completeProof(unsignedCredential, proofConfig, signatureBytes);

    return {
      success: true,
      signedCredential: JSON.stringify(signedCredential),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Signing failed.";
    return { success: false, error: message };
  }
}

/**
 * BUILD_AND_SIGN — full flow: validate + build + sign + optionally package.
 */
async function handleBuildAndSign(
  _event: IpcMainInvokeEvent,
  request: BuildAndSignRequest,
): Promise<BuildAndSignResponse> {
  const signer = loadedSigners.get(request.keyId);
  if (!signer) {
    return { success: false, error: `Key not found: ${request.keyId}` };
  }

  try {
    const result = await buildAndSign(signer, {
      schemaId: request.schemaId,
      issuerDid: request.issuerDid,
      credentialSubject: request.credentialSubject,
      validFrom: request.validFrom,
      validUntil: request.validUntil,
      revocationRegistryUrl: request.revocationRegistryUrl,
      additionalTypes: request.additionalTypes,
      subjectDid: request.subjectDid,
    });

    const response: BuildAndSignResponse = {
      success: true,
      signedCredential: JSON.stringify(result.credential),
    };

    // Package if formats were requested
    if (request.packageFormats && request.packageFormats.length > 0) {
      const formats = request.packageFormats as PackageFormat[];
      const packaging = await packageCredential(result.credential, formats);
      response.packagedOutputs = packaging.outputs.map((output) => ({
        format: output.format,
        data: Buffer.isBuffer(output.data) ? output.data.toString("base64") : output.data,
        mimeType: output.mimeType,
        suggestedFileName: output.suggestedFileName,
      }));
    }

    return response;
  } catch (err) {
    const message = err instanceof Error ? err.message : "Build and sign failed.";
    return { success: false, error: message };
  }
}

// ---------------------------------------------------------------------------
// Verification handler
// ---------------------------------------------------------------------------

/**
 * VERIFY_CREDENTIAL — verify a signed VC offline.
 *
 * Uses @opencred/crypto verifyProof for offline Data Integrity verification.
 * The public key is extracted from the did:key verification method.
 */
async function handleVerifyCredential(
  _event: IpcMainInvokeEvent,
  request: VerifyCredentialRequest,
): Promise<VerifyCredentialResponse> {
  try {
    const parsed = JSON.parse(request.credential);
    const credential = parseCredentialJson(JSON.stringify(parsed));

    // Attempt to resolve the public key from did:key
    const { publicKeyFromMultibase } = await import("@opencred/verification");
    const vm = credential.proof.verificationMethod;

    // Extract the multibase key from the did:key fragment
    const fragment = vm.includes("#") ? vm.split("#")[1] : undefined;
    let publicKey = undefined;
    if (fragment) {
      publicKey = publicKeyFromMultibase(fragment) ?? undefined;
    }

    if (!publicKey) {
      return {
        success: true,
        valid: false,
        message:
          "Unable to resolve public key from verificationMethod. Only did:key is supported for offline verification.",
        checks: [{ name: "key-resolution", passed: false, detail: "Could not resolve public key" }],
      };
    }

    const result = await verifyProof(credential, { publicKey });

    const checks = [
      {
        name: "signature",
        passed: result.verified,
        detail: result.error,
      },
    ];

    // Check dates
    const now = new Date();
    const validFrom = new Date(credential.validFrom);
    const dateChecks: Array<{ name: string; passed: boolean; detail?: string }> = [];

    if (validFrom > now) {
      dateChecks.push({
        name: "not-before",
        passed: false,
        detail: `Credential is not yet valid (validFrom: ${credential.validFrom})`,
      });
    } else {
      dateChecks.push({ name: "not-before", passed: true });
    }

    if (credential.validUntil) {
      const validUntil = new Date(credential.validUntil);
      if (validUntil < now) {
        dateChecks.push({
          name: "expiry",
          passed: false,
          detail: `Credential has expired (validUntil: ${credential.validUntil})`,
        });
      } else {
        dateChecks.push({ name: "expiry", passed: true });
      }
    }

    const allChecks = [...checks, ...dateChecks];
    const allPassed = allChecks.every((c) => c.passed);

    return {
      success: true,
      valid: allPassed,
      message: allPassed
        ? "Credential signature is valid."
        : (allChecks.find((c) => !c.passed)?.detail ?? "Verification failed."),
      checks: allChecks,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Verification failed.";
    return { success: false, error: message };
  }
}

// ---------------------------------------------------------------------------
// Packaging handler
// ---------------------------------------------------------------------------

/**
 * PACKAGE_CREDENTIAL — package a signed VC into various output formats.
 */
async function handlePackageCredential(
  _event: IpcMainInvokeEvent,
  request: PackageCredentialRequest,
): Promise<PackageCredentialResponse> {
  try {
    const credential = parseCredentialJson(request.credential);
    const formats = request.formats as PackageFormat[];
    const result = await packageCredential(credential, formats);

    return {
      success: true,
      outputs: result.outputs.map((output) => ({
        format: output.format,
        data: Buffer.isBuffer(output.data) ? output.data.toString("base64") : output.data,
        mimeType: output.mimeType,
        suggestedFileName: output.suggestedFileName,
      })),
      errors: result.errors,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Packaging failed.";
    return { success: false, errors: [{ format: "unknown", error: message }] };
  }
}

// ---------------------------------------------------------------------------
// Revocation handlers
// ---------------------------------------------------------------------------

/** REVOCATION_QUEUE — queue a credential revocation. */
async function handleRevocationQueue(
  _event: IpcMainInvokeEvent,
  request: RevocationQueueRequest,
): Promise<RevocationQueueResponse> {
  try {
    const item = queueRevocation(request.credentialId, request.registryUrl, {
      revocationHash: request.revocationHash,
      reason: request.reason,
    });

    return {
      success: true,
      item: {
        queueId: item.queueId,
        credentialId: item.credentialId,
        status: item.status,
        queuedAt: item.queuedAt,
      },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to queue revocation.";
    return { success: false, error: message };
  }
}

/** REVOCATION_STATUS — get the current revocation queue status. */
async function handleRevocationStatus(): Promise<RevocationStatusResponse> {
  const items = getQueueItems();
  return {
    items: items.map((item) => ({
      queueId: item.queueId,
      credentialId: item.credentialId,
      registryUrl: item.registryUrl,
      status: item.status,
      queuedAt: item.queuedAt,
      lastAttemptAt: item.lastAttemptAt,
      lastError: item.lastError,
      attemptCount: item.attemptCount,
      reason: item.reason,
    })),
  };
}

/** REVOCATION_PUBLISH — trigger publication of pending revocations. */
async function handleRevocationPublish(): Promise<RevocationPublishResponse> {
  const results = await publishPendingRevocations();
  return { results };
}

// ---------------------------------------------------------------------------
// File operation handlers
// ---------------------------------------------------------------------------

/** FILE_OPEN — show a native open-file dialog and return the file contents. */
async function handleFileOpen(
  _event: IpcMainInvokeEvent,
  request: FileOpenRequest,
): Promise<FileOpenResponse> {
  const result = await dialog.showOpenDialog({
    title: request.title ?? "Open File",
    filters: request.filters ?? [{ name: "All Files", extensions: ["*"] }],
    properties: ["openFile"],
  });

  if (result.canceled || result.filePaths.length === 0) {
    return { content: null, filePath: null };
  }

  const filePath = result.filePaths[0];
  const content = await fs.readFile(filePath, "utf-8");
  return { content, filePath };
}

/** FILE_SAVE — show a native save-file dialog and write contents. */
async function handleFileSave(
  _event: IpcMainInvokeEvent,
  request: FileSaveRequest,
): Promise<FileSaveResponse> {
  const result = await dialog.showSaveDialog({
    defaultPath: request.defaultName,
    filters: request.filters ?? [{ name: "JSON", extensions: ["json"] }],
  });

  if (result.canceled || !result.filePath) {
    return { filePath: null };
  }

  await fs.writeFile(result.filePath, request.content, "utf-8");
  return { filePath: result.filePath };
}

/** GET_OFFLINE_STATUS — return whether the machine appears to be offline. */
async function handleGetOfflineStatus(): Promise<boolean> {
  try {
    const dns = await import("node:dns/promises");
    await dns.lookup("dns.google");
    return false; // online
  } catch {
    return true; // offline
  }
}

/** GET_CONFIG — read a value from electron-store. */
async function handleGetConfig(
  _event: IpcMainInvokeEvent,
  request: ConfigGetRequest,
): Promise<unknown> {
  const store = getStore();
  return store.get(request.key as keyof typeof store.store);
}

/** SET_CONFIG — write a value to electron-store. */
async function handleSetConfig(
  _event: IpcMainInvokeEvent,
  request: ConfigSetRequest,
): Promise<void> {
  const store = getStore();
  store.set(request.key as keyof typeof store.store, request.value);
}

// ---------------------------------------------------------------------------
// Batch issuance handlers
// ---------------------------------------------------------------------------

/**
 * BATCH_START — parse CSV, validate rows, and start batch processing.
 */
async function handleBatchStart(
  _event: IpcMainInvokeEvent,
  request: BatchStartRequest,
): Promise<BatchStartResponse> {
  const signer = loadedSigners.get(request.keyId);
  if (!signer) {
    return { success: false, error: `Key not found: ${request.keyId}` };
  }

  if (batchState.engine) {
    const progress = batchState.engine.getProgress();
    if (progress.running) {
      return { success: false, error: "A batch is already running. Cancel it first." };
    }
  }

  try {
    const parseResult = parseCsv(request.csvContent, {
      schemaId: request.schemaId,
      columnMapping: request.columnMapping,
      delimiter: request.delimiter as Delimiter | undefined,
    });

    batchState.parseResult = parseResult;

    const parseErrors = parseResult.rows
      .filter((r) => !r.valid)
      .map((r) => ({ rowIndex: r.rowIndex, errors: r.errors }));

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: request.schemaId,
      issuerDid: request.issuerDid,
      validFrom: request.validFrom,
      validUntil: request.validUntil,
      revocationRegistryUrl: request.revocationRegistryUrl,
      additionalTypes: request.additionalTypes,
      packageFormats: (request.packageFormats as PackageFormat[]) ?? ["json-ld"],
    });

    batchState.engine = engine;

    void engine.start().then((finalProgress) => {
      batchState.results = finalProgress.rows;
    });

    return {
      success: true,
      headers: parseResult.headers,
      validCount: parseResult.validCount,
      invalidCount: parseResult.invalidCount,
      totalCount: parseResult.totalCount,
      parseErrors: parseErrors.length > 0 ? parseErrors : undefined,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to start batch.";
    return { success: false, error: message };
  }
}

/** BATCH_STATUS — return current batch progress. */
async function handleBatchStatus(): Promise<BatchStatusResponse> {
  if (!batchState.engine) {
    return {
      total: 0,
      completed: 0,
      successCount: 0,
      errorCount: 0,
      skippedCount: 0,
      running: false,
      cancelled: false,
      rows: [],
    };
  }

  const progress = batchState.engine.getProgress();

  return {
    total: progress.total,
    completed: progress.completed,
    successCount: progress.successCount,
    errorCount: progress.errorCount,
    skippedCount: progress.skippedCount,
    running: progress.running,
    cancelled: progress.cancelled,
    rows: progress.rows.map((r) => ({
      rowIndex: r.rowIndex,
      status: r.status,
      error: r.error,
      signedCredential: r.credential ? JSON.stringify(r.credential) : undefined,
    })),
  };
}

/** BATCH_CANCEL — cancel the running batch. */
async function handleBatchCancel(): Promise<BatchCancelResponse> {
  if (!batchState.engine) {
    return { success: false };
  }

  batchState.engine.cancel();
  return { success: true };
}

/** BATCH_EXPORT — export successful batch results as a ZIP archive. */
async function handleBatchExport(
  _event: IpcMainInvokeEvent,
  request: BatchExportRequest,
): Promise<BatchExportResponse> {
  if (!batchState.engine) {
    return { success: false, error: "No batch results available for export." };
  }

  const progress = batchState.engine.getProgress();
  if (progress.running) {
    return { success: false, error: "Batch is still running. Wait for it to complete." };
  }

  try {
    const result = await exportBatchAsZip({
      rows: progress.rows,
      outputPath: request.outputPath,
    });

    return {
      success: true,
      filePath: result.filePath,
      credentialCount: result.credentialCount,
      fileCount: result.fileCount,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Export failed.";
    return { success: false, error: message };
  }
}

// ---------------------------------------------------------------------------
// PKCS#11 hardware token handlers
// ---------------------------------------------------------------------------

/**
 * PKCS11_DETECT — check if a PKCS#11 library exists at the given path.
 */
async function handlePkcs11Detect(
  _event: IpcMainInvokeEvent,
  request: Pkcs11DetectRequest,
): Promise<Pkcs11DetectResponse> {
  try {
    const stat = await fs.stat(request.libraryPath);
    if (!stat.isFile()) {
      return { exists: false, error: "Path is not a file" };
    }

    const ext = request.libraryPath.toLowerCase();
    const validExtensions = [".so", ".dll", ".dylib"];
    const hasValidExt = validExtensions.some((e) => ext.endsWith(e));
    if (!hasValidExt) {
      return {
        exists: true,
        error: "File does not have a shared library extension (.so, .dll, .dylib)",
      };
    }

    return { exists: true };
  } catch {
    return { exists: false, error: "File not found" };
  }
}

/**
 * PKCS11_LIST_SLOTS — enumerate PKCS#11 slots/tokens.
 */
async function handlePkcs11ListSlots(
  _event: IpcMainInvokeEvent,
  request: Pkcs11ListSlotsRequest,
): Promise<Pkcs11ListSlotsResponse> {
  let p11;
  try {
    const {
      initializePkcs11,
      finalizePkcs11,
      listSlots: listPkcs11Slots,
    } = await import("../signing/pkcs11-session.js");
    p11 = initializePkcs11(request.libraryPath);
    const slots = listPkcs11Slots(p11);
    finalizePkcs11(p11);

    return {
      success: true,
      slots: slots.map((s) => ({
        index: s.index,
        description: s.description,
        tokenPresent: s.tokenPresent,
        tokenLabel: s.tokenLabel,
        tokenManufacturer: s.tokenManufacturer,
      })),
    };
  } catch (err) {
    if (p11) {
      const { finalizePkcs11 } = await import("../signing/pkcs11-session.js");
      finalizePkcs11(p11);
    }
    const message = err instanceof Error ? err.message : "Failed to list PKCS#11 slots.";
    return { success: false, error: message };
  }
}

/**
 * PKCS11_LIST_KEYS — list keys on a specific token.
 */
async function handlePkcs11ListKeys(
  _event: IpcMainInvokeEvent,
  request: Pkcs11ListKeysRequest,
): Promise<Pkcs11ListKeysResponse> {
  let p11;
  let session;
  try {
    const {
      initializePkcs11,
      finalizePkcs11,
      openSession: openPkcs11Session,
      closeSession: closePkcs11Session,
      listKeys: listPkcs11Keys,
    } = await import("../signing/pkcs11-session.js");
    p11 = initializePkcs11(request.libraryPath);
    session = openPkcs11Session(p11, request.slotIndex, request.pin);
    const keys = listPkcs11Keys(session);
    closePkcs11Session(session);
    finalizePkcs11(p11);

    return {
      success: true,
      keys: keys.map((k) => ({
        label: k.label,
        id: k.id,
        keyType: k.keyType,
        hasPublicKey: k.hasPublicKey,
      })),
    };
  } catch (err) {
    const pkcs11Session = await import("../signing/pkcs11-session.js").catch(() => null);
    if (session && pkcs11Session) {
      pkcs11Session.closeSession(session);
    }
    if (p11 && pkcs11Session) {
      pkcs11Session.finalizePkcs11(p11);
    }
    const message = err instanceof Error ? err.message : "Failed to list keys.";
    return { success: false, error: message };
  }
}

/**
 * PKCS11_CONNECT — open a persistent session and make a key available for signing.
 */
async function handlePkcs11Connect(
  _event: IpcMainInvokeEvent,
  request: Pkcs11ConnectRequest,
): Promise<Pkcs11ConnectResponse> {
  try {
    const { createPkcs11Signer } = await import("../signing/pkcs11-signer.js");
    const { signer, availableKeys } = createPkcs11Signer({
      libraryPath: request.libraryPath,
      slotIndex: request.slotIndex,
      pin: request.pin,
      keyId: request.keyId,
      label: request.label,
    });

    const meta: KeyMetadata = {
      id: signer.id,
      fingerprint: signer.metadata.fingerprint,
      algorithm: "ECDSA P-256",
      importedAt: new Date().toISOString(),
      label: signer.metadata.label,
      format: "pkcs11",
      source: "pkcs11",
    };

    importedKeys.set(signer.id, meta);
    loadedSigners.set(signer.id, signer);

    return {
      success: true,
      key: meta,
      availableKeys: availableKeys.map((k) => ({
        label: k.label,
        id: k.id,
        keyType: k.keyType,
        hasPublicKey: k.hasPublicKey,
      })),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to connect to hardware token.";
    return { success: false, error: message };
  }
}

// ---------------------------------------------------------------------------
// Auto-update handlers
// ---------------------------------------------------------------------------

/** UPDATE_CHECK — manually trigger an update check. */
async function handleUpdateCheck(): Promise<UpdateStatusResponse> {
  return await checkForUpdates();
}

/** UPDATE_DOWNLOAD — start downloading an available update. */
async function handleUpdateDownload(): Promise<UpdateStatusResponse> {
  return await downloadUpdate();
}

/** UPDATE_INSTALL — quit and install a downloaded update. */
async function handleUpdateInstall(): Promise<void> {
  quitAndInstall();
}

/** UPDATE_STATUS — return the current update status snapshot. */
async function handleUpdateStatus(): Promise<UpdateStatusResponse> {
  return getUpdateStatus();
}

// ---------------------------------------------------------------------------
// OS certificate store handlers
// ---------------------------------------------------------------------------

/**
 * OSCERT_LIST — enumerate certificates from the OS certificate store.
 *
 * Detects the runtime platform and dispatches to the appropriate provider.
 */
async function handleOsCertList(): Promise<OsCertListResponse> {
  try {
    const platform = process.platform as "darwin" | "win32" | "linux";
    const { listOsCertificates } = await import("../signing/os-cert-signer.js");
    const result = await listOsCertificates(platform);

    return {
      success: true,
      certificates: result.certificates,
      platform: result.platform,
      storeName: result.storeName,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to list OS certificates.";
    return { success: false, error: message };
  }
}

/**
 * OSCERT_SIGN — sign data using an OS certificate's private key.
 *
 * The private key never leaves the OS. Data is passed as base64.
 */
async function handleOsCertSign(
  _event: IpcMainInvokeEvent,
  request: OsCertSignRequest,
): Promise<OsCertSignResponse> {
  // Look up the signer in loadedSigners
  // The signer was registered via OSCERT_CONNECT
  const matchingSigner = Array.from(loadedSigners.values()).find(
    (s) =>
      s.type === "os-cert" && importedKeys.get(s.id)?.format === `oscert:${request.certificateId}`,
  );

  if (!matchingSigner) {
    return {
      success: false,
      error: "OS certificate not connected. Use oscert:connect first.",
    };
  }

  try {
    const data = Buffer.from(request.data, "base64");
    const signature = await matchingSigner.sign(new Uint8Array(data));

    return {
      success: true,
      signature: Buffer.from(signature).toString("base64"),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "OS certificate signing failed.";
    return { success: false, error: message };
  }
}

/**
 * OSCERT_CONNECT — select an OS certificate and create a signer.
 *
 * Creates an OsCertSigner from the certificate, registers it in the
 * loadedSigners map, and returns key metadata for the UI.
 */
async function handleOsCertConnect(
  _event: IpcMainInvokeEvent,
  request: OsCertConnectRequest,
): Promise<OsCertConnectResponse> {
  try {
    const platform = process.platform as "darwin" | "win32" | "linux";

    const { createOsCertSigner } = await import("../signing/os-cert-signer.js");
    const { signer } = await createOsCertSigner({
      platform,
      certificateId: request.certificateId,
      label: request.label,
    });

    const meta: KeyMetadata = {
      id: signer.id,
      fingerprint: signer.metadata.fingerprint,
      algorithm: "ECDSA P-256",
      importedAt: new Date().toISOString(),
      label: request.label,
      format: `oscert:${request.certificateId}`,
      source: "os-cert",
    };

    importedKeys.set(signer.id, meta);
    loadedSigners.set(signer.id, signer);

    return {
      success: true,
      key: meta,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to connect OS certificate.";
    return { success: false, error: message };
  }
}

// ---------------------------------------------------------------------------
// Registration / cleanup
// ---------------------------------------------------------------------------

/**
 * Register all IPC handlers. Call once during app initialisation.
 */
export function registerIpcHandlers(): void {
  // Key management
  ipcMain.handle(IPC_CHANNELS.KEY_IMPORT, handleKeyImport);
  ipcMain.handle(IPC_CHANNELS.KEY_LIST, handleKeyList);
  ipcMain.handle(IPC_CHANNELS.KEY_GENERATE, handleKeyGenerate);

  // Schema
  ipcMain.handle(IPC_CHANNELS.SCHEMA_LIST, handleSchemaList);
  ipcMain.handle(IPC_CHANNELS.SCHEMA_GET, handleSchemaGet);

  // Signing
  ipcMain.handle(IPC_CHANNELS.SIGN_CREDENTIAL, handleSignCredential);
  ipcMain.handle(IPC_CHANNELS.BUILD_AND_SIGN, handleBuildAndSign);

  // Verification
  ipcMain.handle(IPC_CHANNELS.VERIFY_CREDENTIAL, handleVerifyCredential);

  // Packaging
  ipcMain.handle(IPC_CHANNELS.PACKAGE_CREDENTIAL, handlePackageCredential);

  // Revocation
  ipcMain.handle(IPC_CHANNELS.REVOCATION_QUEUE, handleRevocationQueue);
  ipcMain.handle(IPC_CHANNELS.REVOCATION_STATUS, handleRevocationStatus);
  ipcMain.handle(IPC_CHANNELS.REVOCATION_PUBLISH, handleRevocationPublish);

  // Batch issuance
  ipcMain.handle(IPC_CHANNELS.BATCH_START, handleBatchStart);
  ipcMain.handle(IPC_CHANNELS.BATCH_STATUS, handleBatchStatus);
  ipcMain.handle(IPC_CHANNELS.BATCH_CANCEL, handleBatchCancel);
  ipcMain.handle(IPC_CHANNELS.BATCH_EXPORT, handleBatchExport);

  // File operations
  ipcMain.handle(IPC_CHANNELS.FILE_OPEN, handleFileOpen);
  ipcMain.handle(IPC_CHANNELS.FILE_SAVE, handleFileSave);

  // Network status
  ipcMain.handle(IPC_CHANNELS.GET_OFFLINE_STATUS, handleGetOfflineStatus);

  // PKCS#11 hardware tokens
  ipcMain.handle(IPC_CHANNELS.PKCS11_DETECT, handlePkcs11Detect);
  ipcMain.handle(IPC_CHANNELS.PKCS11_LIST_SLOTS, handlePkcs11ListSlots);
  ipcMain.handle(IPC_CHANNELS.PKCS11_LIST_KEYS, handlePkcs11ListKeys);
  ipcMain.handle(IPC_CHANNELS.PKCS11_CONNECT, handlePkcs11Connect);

  // Auto-update
  ipcMain.handle(IPC_CHANNELS.UPDATE_CHECK, handleUpdateCheck);
  ipcMain.handle(IPC_CHANNELS.UPDATE_DOWNLOAD, handleUpdateDownload);
  ipcMain.handle(IPC_CHANNELS.UPDATE_INSTALL, handleUpdateInstall);
  ipcMain.handle(IPC_CHANNELS.UPDATE_STATUS, handleUpdateStatus);

  // OS certificate store
  ipcMain.handle(IPC_CHANNELS.OSCERT_LIST, handleOsCertList);
  ipcMain.handle(IPC_CHANNELS.OSCERT_SIGN, handleOsCertSign);
  ipcMain.handle(IPC_CHANNELS.OSCERT_CONNECT, handleOsCertConnect);

  // Config
  ipcMain.handle(IPC_CHANNELS.GET_CONFIG, handleGetConfig);
  ipcMain.handle(IPC_CHANNELS.SET_CONFIG, handleSetConfig);
}

/**
 * Remove all IPC handlers. Call during app shutdown.
 */
export function cleanupIpcHandlers(): void {
  for (const channel of Object.values(IPC_CHANNELS)) {
    ipcMain.removeHandler(channel);
  }
}
