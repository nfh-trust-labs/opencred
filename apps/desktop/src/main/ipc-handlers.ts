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

import { app, ipcMain, dialog, type IpcMainInvokeEvent } from "electron";
import * as os from "node:os";
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
  RevocationPublishRequest,
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
  AttestationImportRequest,
  AttestationImportResponse,
  AttestationGetRequest,
  AttestationGetResponse,
  AttestationListResponse,
  AttestationRemoveRequest,
  AttestationRemoveResponse,
  AttestationCheckRequest,
  AttestationCheckResponse,
  CredentialHistoryAddRequest,
  CredentialHistoryListResponse,
  CredentialHistoryDeleteRequest,
  CredentialHistoryDeleteResponse,
  CustomSchemaSaveRequest,
  CustomSchemaSaveResponse,
  CustomSchemaListResponse,
  CustomSchemaDeleteRequest,
  CustomSchemaDeleteResponse,
  AttestationRequestChallengeRequest,
  AttestationRequestChallengeResponse,
  AttestationSubmitVerificationRequest,
  AttestationSubmitVerificationResponse,
  AttestationSubmitBusinessVcRequest,
  AttestationSubmitBusinessVcResponse,
  SystemInfoResponse,
  LogTailResponse,
} from "../shared/ipc-types.js";
import { getLogFilePath, readRecentLogs } from "./logger.js";
import {
  storeAttestation,
  getAttestation,
  listAttestations,
  removeAttestation,
  hasAttestation,
} from "./attestation-store.js";
import { getStore, restrictStoreFilePermissions, CREDENTIAL_HISTORY_CAP } from "./store.js";
import type { CredentialHistoryEntry, CustomSchemaEntry } from "./store.js";
import { createSoftwareSigner, buildSigner } from "../signing/software-signer.js";
import { buildAndSign, listSchemas, getSchemaDefinition } from "../signing/local-signing-flow.js";
import { signWithFormat } from "../signing/proof-format-router.js";
import type { UiProofFormat } from "../shared/ipc-types.js";
import { generateKeyPairSync, createPublicKey, randomUUID } from "node:crypto";
import { verifyProof } from "@opencred/crypto";
import { packageCredential } from "../packaging/packager.js";
import type { PackageFormat } from "../packaging/packager.js";
import { parseCredentialJson } from "../packaging/json-export.js";
import { CryptoError, ValidationError, SchemaValidationError } from "@opencred/shared";
import {
  packageCredential as packageCredentialWithTemplates,
} from "./credential-export.js";
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


import { BATCH_ROW_LIMIT } from "../shared/constants.js";

// ---------------------------------------------------------------------------
// In-memory registries
// ---------------------------------------------------------------------------

/** Maps key ID (did:key VM ID) -> key metadata for display. */
const importedKeys = new Map<string, KeyMetadata>();

/** Maps key ID -> Signer instance (private key stays in memory, never serialized). */
const loadedSigners = new Map<string, Signer>();

/**
 * Maps key ID -> public key JWK for generated keys.
 * Stays in the main process — never exposed to the renderer.
 * Used when requesting attestation from the OpenCred API.
 */
const loadedPublicKeyJwks = new Map<string, Record<string, unknown>>();

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
    const { signer, format } = createSoftwareSigner(request.filePath, request.label, request.password);

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

    // Store public key JWK for attestation requests (never crosses IPC).
    const jwk = publicKey.export({ format: "jwk" });
    loadedPublicKeyJwks.set(signer.id, jwk as Record<string, unknown>);

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
 *
 * When `inlineSchema` is provided (blank/custom credentials), schema registry
 * validation is skipped and the credential is built directly from the inline
 * schema definition.
 */
async function handleBuildAndSign(
  _event: IpcMainInvokeEvent,
  request: BuildAndSignRequest,
): Promise<BuildAndSignResponse> {
  const signer = loadedSigners.get(request.keyId);
  if (!signer) {
    return { success: false, error: `Key not found: ${request.keyId}`, errorCode: "KEY_NOT_FOUND" };
  }

  const proofFormat: UiProofFormat = request.proofFormat ?? "vc-jwt";

  // Pre-signing validation: Data Integrity requires ECDSA or EdDSA
  if (proofFormat === "data-integrity" && signer.algorithm.startsWith("RSA")) {
    return {
      success: false,
      error: "Data Integrity proofs require ECDSA or EdDSA keys. Your key uses RSA — please select VC-JWT or SD-JWT-VC.",
      errorCode: "INCOMPATIBLE_FORMAT",
      errorField: "proofFormat",
    };
  }

  try {
    let signedCredentialJson: string;
    let isCompactToken = false;

    if (request.inlineSchema) {
      // Blank/custom credential — skip schema registry, use proof format router.
      const { CredentialBuilder } = await import("@opencred/vc-core");

      const builder = new CredentialBuilder()
        .setIssuer(request.issuerDid)
        .setValidFrom(request.validFrom);

      const subject: Record<string, unknown> = { ...request.credentialSubject };
      if (request.subjectDid) {
        subject["id"] = request.subjectDid;
      }
      builder.setCredentialSubject(subject);

      if (request.additionalTypes) {
        for (const type of request.additionalTypes) {
          builder.addType(type);
        }
      }
      if (request.validUntil) {
        builder.setValidUntil(request.validUntil);
      }
      if (request.revocationRegistryUrl) {
        builder.setCredentialStatus({
          id: request.revocationRegistryUrl,
          type: "DeDiRevocationListStatusV1",
          statusPurpose: "revocation",
        });
      }
      if (request.credentialSchemaUrl) {
        builder.setSchema({ id: request.credentialSchemaUrl, type: "JsonSchema" });
      }

      const unsigned = builder.build();

      const vct = request.additionalTypes?.[0] ?? request.schemaId;
      const result = await signWithFormat(signer, unsigned, proofFormat, {
        verificationMethod: signer.id,
        selectiveDisclosureClaims: request.selectiveDisclosureClaims,
        vct,
      });
      signedCredentialJson = result.signedOutput;
      isCompactToken = result.isCompactToken;
    } else {
      const result = await buildAndSign(signer, {
        schemaId: request.schemaId,
        issuerDid: request.issuerDid,
        credentialSubject: request.credentialSubject,
        validFrom: request.validFrom,
        validUntil: request.validUntil,
        revocationRegistryUrl: request.revocationRegistryUrl,
        additionalTypes: request.additionalTypes,
        subjectDid: request.subjectDid,
        proofFormat,
        selectiveDisclosureClaims: request.selectiveDisclosureClaims,
        credentialSchemaUrl: request.credentialSchemaUrl,
      });
      signedCredentialJson = typeof result.credential === "string"
        ? result.credential
        : JSON.stringify(result.credential);
      isCompactToken = result.isCompactToken;
    }

    const response: BuildAndSignResponse = {
      success: true,
      signedCredential: signedCredentialJson,
      proofFormat,
    };

    // Package if formats were requested (only for JSON-based outputs)
    if (!isCompactToken && request.packageFormats && request.packageFormats.length > 0) {
      const formats = request.packageFormats as PackageFormat[];
      const parsed = parseCredentialJson(signedCredentialJson);
      const packaging = await packageCredential(parsed, formats);
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
    let errorCode = "UNKNOWN_ERROR";
    let errorField: string | undefined;

    if (err instanceof SchemaValidationError) {
      errorCode = "SCHEMA_VALIDATION_ERROR";
      errorField = (err as { field?: string }).field;
    } else if (err instanceof CryptoError) {
      errorCode = "SIGNING_ERROR";
    } else if (err instanceof ValidationError) {
      errorCode = "VALIDATION_ERROR";
    }

    return { success: false, error: message, errorCode, errorField };
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
 *
 * Supports both the legacy packager formats (qr-png, qr-svg, pdf, json-ld,
 * json-compact) and the new template-aware formats (svg, qr, json-ld).
 * When "svg" format is requested, the template renderer from
 * credential-export.ts is used, applying schemaId and customization options.
 */
async function handlePackageCredential(
  _event: IpcMainInvokeEvent,
  request: PackageCredentialRequest,
): Promise<PackageCredentialResponse> {
  try {
    const credential = parseCredentialJson(request.credential);

    // Partition formats: template-aware formats vs legacy packager formats.
    const templateFormats = ["svg", "qr", "json-ld"];
    const templateRequested = request.formats.filter((f) => templateFormats.includes(f));
    const legacyRequested = request.formats.filter((f) => !templateFormats.includes(f));

    const allOutputs: Array<{
      format: string;
      data: string;
      mimeType: string;
      suggestedFileName: string;
    }> = [];
    const allErrors: Array<{ format: string; error: string }> = [];

    // Process template-aware formats
    if (templateRequested.length > 0) {
      try {
        const templateOutputs = await packageCredentialWithTemplates(
          credential,
          request.schemaId ?? "default",
          templateRequested,
          request.customization,
        );

        for (const output of templateOutputs) {
          allOutputs.push({
            format: output.format,
            data: output.data,
            mimeType: output.mimeType,
            suggestedFileName: output.suggestedFileName,
          });
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : "Template packaging failed.";
        for (const fmt of templateRequested) {
          allErrors.push({ format: fmt, error: message });
        }
      }
    }

    // Process legacy packager formats
    if (legacyRequested.length > 0) {
      const legacyFormats = legacyRequested as PackageFormat[];
      const result = await packageCredential(credential, legacyFormats);

      for (const output of result.outputs) {
        allOutputs.push({
          format: output.format,
          data: Buffer.isBuffer(output.data) ? output.data.toString("base64") : output.data,
          mimeType: output.mimeType,
          suggestedFileName: output.suggestedFileName,
        });
      }

      allErrors.push(...result.errors);
    }

    return {
      success: true,
      outputs: allOutputs,
      errors: allErrors.length > 0 ? allErrors : undefined,
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
async function handleRevocationPublish(
  _event: IpcMainInvokeEvent,
  request: RevocationPublishRequest,
): Promise<RevocationPublishResponse> {
  const results = await publishPendingRevocations(request.dediCredentials, request.dediBaseUrl);
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

  if (request.encoding === "base64") {
    await fs.writeFile(result.filePath, Buffer.from(request.content, "base64"));
  } else {
    await fs.writeFile(result.filePath, request.content, "utf-8");
  }
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
    // Lightweight pre-check: count data lines before full parsing to prevent
    // excessive memory/CPU usage on very large CSVs.
    const lineCount = request.csvContent.split(/\r?\n/).filter((l) => l.trim().length > 0).length - 1;
    if (lineCount > BATCH_ROW_LIMIT) {
      return {
        success: false,
        error: `Batch exceeds maximum of 1,000 rows (found ~${lineCount}). Please split your CSV into smaller files.`,
      };
    }

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
      proofFormat: request.proofFormat,
      selectiveDisclosureClaims: request.selectiveDisclosureClaims,
      credentialSchemaUrl: request.credentialSchemaUrl,
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
// Attestation handlers (Quick Start / Workflow 3)
// ---------------------------------------------------------------------------

/** ATTESTATION_IMPORT — store a Key Attestation VC. */
async function handleAttestationImport(
  _event: IpcMainInvokeEvent,
  request: AttestationImportRequest,
): Promise<AttestationImportResponse> {
  try {
    const stored = storeAttestation(request.keyId, request.credential);
    return {
      success: true,
      attestation: {
        keyId: stored.keyId,
        organizationName: stored.organizationName,
        verifiedDomain: stored.verifiedDomain,
        validFrom: stored.validFrom,
        validUntil: stored.validUntil,
        storedAt: stored.storedAt,
      },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to store attestation.";
    return { success: false, error: message };
  }
}

/** ATTESTATION_GET — retrieve attestation for a key. */
async function handleAttestationGet(
  _event: IpcMainInvokeEvent,
  request: AttestationGetRequest,
): Promise<AttestationGetResponse> {
  const stored = getAttestation(request.keyId);
  if (!stored) return { attestation: null };
  return {
    attestation: {
      keyId: stored.keyId,
      credential: stored.credential,
      organizationName: stored.organizationName,
      verifiedDomain: stored.verifiedDomain,
      validFrom: stored.validFrom,
      validUntil: stored.validUntil,
      storedAt: stored.storedAt,
    },
  };
}

/** ATTESTATION_LIST — list all attestation metadata. */
async function handleAttestationList(): Promise<AttestationListResponse> {
  const all = listAttestations();
  return {
    attestations: all.map((a) => ({
      keyId: a.keyId,
      organizationName: a.organizationName,
      verifiedDomain: a.verifiedDomain,
      validFrom: a.validFrom,
      validUntil: a.validUntil,
      storedAt: a.storedAt,
    })),
  };
}

/** ATTESTATION_REMOVE — remove an attestation. */
async function handleAttestationRemove(
  _event: IpcMainInvokeEvent,
  request: AttestationRemoveRequest,
): Promise<AttestationRemoveResponse> {
  return { removed: removeAttestation(request.keyId) };
}

/** ATTESTATION_CHECK — check if a key has an attestation. */
async function handleAttestationCheck(
  _event: IpcMainInvokeEvent,
  request: AttestationCheckRequest,
): Promise<AttestationCheckResponse> {
  return { hasAttestation: hasAttestation(request.keyId) };
}

// ---------------------------------------------------------------------------
// Credential history handlers
// ---------------------------------------------------------------------------

/** CREDENTIAL_HISTORY_LIST — return all credential history entries. */
async function handleCredentialHistoryList(): Promise<CredentialHistoryListResponse> {
  const store = getStore();
  const history = (store.get("credentialHistory" as keyof typeof store.store) as CredentialHistoryEntry[]) ?? [];
  return { entries: history };
}

/** CREDENTIAL_HISTORY_ADD — add a credential to history (FIFO cap). */
async function handleCredentialHistoryAdd(
  _event: IpcMainInvokeEvent,
  request: CredentialHistoryAddRequest,
): Promise<CredentialHistoryEntry> {
  const store = getStore();
  const history = (store.get("credentialHistory" as keyof typeof store.store) as CredentialHistoryEntry[]) ?? [];

  const entry: CredentialHistoryEntry = {
    id: randomUUID(),
    schemaId: request.schemaId,
    schemaName: request.schemaName,
    subjectSummary: request.subjectSummary,
    issuedAt: new Date().toISOString(),
    credentialJson: request.credentialJson,
    keyFingerprint: request.keyFingerprint,
    proofFormat: request.proofFormat,
  };

  // Prepend new entry, cap at limit
  const updated = [entry, ...history].slice(0, CREDENTIAL_HISTORY_CAP);
  store.set("credentialHistory" as keyof typeof store.store, updated);
  return entry;
}

/** CREDENTIAL_HISTORY_DELETE — remove a credential from history. */
async function handleCredentialHistoryDelete(
  _event: IpcMainInvokeEvent,
  request: CredentialHistoryDeleteRequest,
): Promise<CredentialHistoryDeleteResponse> {
  const store = getStore();
  const history = (store.get("credentialHistory" as keyof typeof store.store) as CredentialHistoryEntry[]) ?? [];
  const filtered = history.filter((e) => e.id !== request.id);
  const deleted = filtered.length < history.length;
  store.set("credentialHistory" as keyof typeof store.store, filtered);
  return { deleted };
}

// ---------------------------------------------------------------------------
// Custom schema handlers
// ---------------------------------------------------------------------------

/** CUSTOM_SCHEMA_LIST — return all custom schemas. */
async function handleCustomSchemaList(): Promise<CustomSchemaListResponse> {
  const store = getStore();
  const schemas = (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];
  return { schemas };
}

/** CUSTOM_SCHEMA_SAVE — create or update a custom schema. */
async function handleCustomSchemaSave(
  _event: IpcMainInvokeEvent,
  request: CustomSchemaSaveRequest,
): Promise<CustomSchemaSaveResponse> {
  const store = getStore();
  const schemas = (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];

  if (request.id) {
    // Update existing
    const idx = schemas.findIndex((s) => s.id === request.id);
    if (idx >= 0) {
      schemas[idx] = { ...schemas[idx], name: request.name, schema: request.schema };
      store.set("customSchemas" as keyof typeof store.store, schemas);
      return schemas[idx];
    }
  }

  // Create new
  const entry: CustomSchemaEntry = {
    id: `custom:${randomUUID()}`,
    name: request.name,
    schema: request.schema,
    createdAt: new Date().toISOString(),
  };
  store.set("customSchemas" as keyof typeof store.store, [...schemas, entry]);
  return entry;
}

/** CUSTOM_SCHEMA_DELETE — remove a custom schema. */
async function handleCustomSchemaDelete(
  _event: IpcMainInvokeEvent,
  request: CustomSchemaDeleteRequest,
): Promise<CustomSchemaDeleteResponse> {
  const store = getStore();
  const schemas = (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];
  const filtered = schemas.filter((s) => s.id !== request.id);
  const deleted = filtered.length < schemas.length;
  store.set("customSchemas" as keyof typeof store.store, filtered);
  return { deleted };
}

// ---------------------------------------------------------------------------
// System / diagnostics handlers
// ---------------------------------------------------------------------------

/** SYSTEM_INFO — return app version, OS, Electron/Node versions, log path. */
async function handleSystemInfo(): Promise<SystemInfoResponse> {
  return {
    appVersion: app.getVersion(),
    electronVersion: process.versions.electron ?? "unknown",
    nodeVersion: process.versions.node,
    os: process.platform,
    osVersion: os.release(),
    arch: process.arch,
    logPath: getLogFilePath(),
  };
}

/** LOG_TAIL — read recent lines from the log file. */
async function handleLogTail(
  _event: IpcMainInvokeEvent,
  request?: { lines?: number },
): Promise<LogTailResponse> {
  const lines = request?.lines ?? 200;
  const logs = await readRecentLogs(lines);
  return { logs, logPath: getLogFilePath() };
}

// ---------------------------------------------------------------------------
// Attestation API handlers (OpenCred-Attested onboarding)
// ---------------------------------------------------------------------------

/**
 * Resolve the OpenCred attestation API URL from config.
 * Defaults to https://api.opencred.dev if not set.
 */
function getAttestationApiUrl(): string {
  const store = getStore();
  return store.get("opencredApiUrl");
}

/**
 * Validate that the API URL is acceptable (https or localhost).
 */
function validateApiUrl(url: string): string | null {
  if (url.startsWith("https://") || url.startsWith("http://localhost")) {
    return null;
  }
  return "API URL must use HTTPS or http://localhost";
}

/**
 * ATTESTATION_REQUEST_CHALLENGE — request a domain verification challenge.
 *
 * Proxies to the OpenCred attestation API to create a DNS TXT or HTTP
 * verification challenge for domain ownership proof.
 */
async function handleAttestationRequestChallenge(
  _event: IpcMainInvokeEvent,
  request: AttestationRequestChallengeRequest,
): Promise<AttestationRequestChallengeResponse> {
  try {
    const apiUrl = getAttestationApiUrl();
    const urlError = validateApiUrl(apiUrl);
    if (urlError) {
      return { success: false, error: urlError };
    }

    const response = await fetch(`${apiUrl}/attestation/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: request.domain, method: request.method }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      return { success: false, error: `API error (${response.status}): ${body || response.statusText}` };
    }

    const data = (await response.json()) as Record<string, unknown>;
    return {
      success: true,
      challengeId: data.challengeId as string | undefined,
      token: data.token as string | undefined,
      instructions: data.instructions as string | undefined,
      expiresAt: data.expiresAt as string | undefined,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to request challenge.";
    return { success: false, error: message };
  }
}

/**
 * ATTESTATION_SUBMIT_VERIFICATION — verify domain ownership and request attestation.
 *
 * Sends the public key JWK (from the main process registry) along with
 * challenge verification data. On success, stores the attestation credential.
 *
 * SECURITY: The public key JWK is read from loadedPublicKeyJwks (main process
 * only). It is never received from the renderer.
 */
async function handleAttestationSubmitVerification(
  _event: IpcMainInvokeEvent,
  request: AttestationSubmitVerificationRequest,
): Promise<AttestationSubmitVerificationResponse> {
  try {
    const apiUrl = getAttestationApiUrl();
    const urlError = validateApiUrl(apiUrl);
    if (urlError) {
      return { success: false, error: urlError };
    }

    const publicKeyJwk = loadedPublicKeyJwks.get(request.keyId);
    if (!publicKeyJwk) {
      return { success: false, error: "Key not found or not a generated key" };
    }

    const metadata = importedKeys.get(request.keyId);
    if (!metadata) {
      return { success: false, error: "Key metadata not found" };
    }

    const response = await fetch(`${apiUrl}/attestation/challenge/${request.challengeId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        publicKeyJwk,
        issuerDid: metadata.id,
        keyFingerprint: metadata.fingerprint,
        keyAlgorithm: "P-256",
        verificationMethodId: request.keyId,
        organizationName: request.organizationName,
      }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      return { success: false, error: `API error (${response.status}): ${body || response.statusText}` };
    }

    const data = (await response.json()) as Record<string, unknown>;
    const credential = (data.credential ?? data) as Record<string, unknown>;

    // Store the attestation locally
    storeAttestation(request.keyId, credential);

    return { success: true, credential };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Verification submission failed.";
    return { success: false, error: message };
  }
}

/**
 * ATTESTATION_SUBMIT_BUSINESS_VC — submit a business VC for attestation.
 *
 * Alternative to domain verification: the issuer provides a business VC
 * that OpenCred validates, then attests the public key.
 *
 * SECURITY: Same as above — public key JWK stays in main process.
 */
async function handleAttestationSubmitBusinessVc(
  _event: IpcMainInvokeEvent,
  request: AttestationSubmitBusinessVcRequest,
): Promise<AttestationSubmitBusinessVcResponse> {
  try {
    const apiUrl = getAttestationApiUrl();
    const urlError = validateApiUrl(apiUrl);
    if (urlError) {
      return { success: false, error: urlError };
    }

    const publicKeyJwk = loadedPublicKeyJwks.get(request.keyId);
    if (!publicKeyJwk) {
      return { success: false, error: "Key not found or not a generated key" };
    }

    const metadata = importedKeys.get(request.keyId);
    if (!metadata) {
      return { success: false, error: "Key metadata not found" };
    }

    const response = await fetch(`${apiUrl}/attestation/attest-by-vc`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        businessVc: request.businessVc,
        publicKeyJwk,
        issuerDid: metadata.id,
        keyFingerprint: metadata.fingerprint,
        keyAlgorithm: "P-256",
        verificationMethodId: request.keyId,
      }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      return { success: false, error: `API error (${response.status}): ${body || response.statusText}` };
    }

    const data = (await response.json()) as Record<string, unknown>;
    const credential = (data.credential ?? data) as Record<string, unknown>;

    // Store the attestation locally
    storeAttestation(request.keyId, credential);

    return { success: true, credential };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Business VC attestation failed.";
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

  // Attestation (Quick Start / Workflow 3)
  ipcMain.handle(IPC_CHANNELS.ATTESTATION_IMPORT, handleAttestationImport);
  ipcMain.handle(IPC_CHANNELS.ATTESTATION_GET, handleAttestationGet);
  ipcMain.handle(IPC_CHANNELS.ATTESTATION_LIST, handleAttestationList);
  ipcMain.handle(IPC_CHANNELS.ATTESTATION_REMOVE, handleAttestationRemove);
  ipcMain.handle(IPC_CHANNELS.ATTESTATION_CHECK, handleAttestationCheck);

  // Attestation API (OpenCred-Attested onboarding)
  ipcMain.handle(IPC_CHANNELS.ATTESTATION_REQUEST_CHALLENGE, handleAttestationRequestChallenge);
  ipcMain.handle(IPC_CHANNELS.ATTESTATION_SUBMIT_VERIFICATION, handleAttestationSubmitVerification);
  ipcMain.handle(IPC_CHANNELS.ATTESTATION_SUBMIT_BUSINESS_VC, handleAttestationSubmitBusinessVc);

  // Credential history
  ipcMain.handle(IPC_CHANNELS.CREDENTIAL_HISTORY_LIST, handleCredentialHistoryList);
  ipcMain.handle(IPC_CHANNELS.CREDENTIAL_HISTORY_ADD, handleCredentialHistoryAdd);
  ipcMain.handle(IPC_CHANNELS.CREDENTIAL_HISTORY_DELETE, handleCredentialHistoryDelete);

  // Custom schemas
  ipcMain.handle(IPC_CHANNELS.CUSTOM_SCHEMA_SAVE, handleCustomSchemaSave);
  ipcMain.handle(IPC_CHANNELS.CUSTOM_SCHEMA_LIST, handleCustomSchemaList);
  ipcMain.handle(IPC_CHANNELS.CUSTOM_SCHEMA_DELETE, handleCustomSchemaDelete);

  // Config
  ipcMain.handle(IPC_CHANNELS.GET_CONFIG, handleGetConfig);
  ipcMain.handle(IPC_CHANNELS.SET_CONFIG, handleSetConfig);

  // System / diagnostics
  ipcMain.handle(IPC_CHANNELS.SYSTEM_INFO, handleSystemInfo);
  ipcMain.handle(IPC_CHANNELS.LOG_TAIL, handleLogTail);
}

/**
 * Remove all IPC handlers. Call during app shutdown.
 */
export function cleanupIpcHandlers(): void {
  for (const channel of Object.values(IPC_CHANNELS)) {
    ipcMain.removeHandler(channel);
  }
}
