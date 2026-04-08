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

import { app, ipcMain, dialog, safeStorage, type IpcMainInvokeEvent } from "electron";
import * as os from "node:os";
import * as fs from "node:fs/promises";
import { isIP } from "node:net";
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
  CredentialHistoryAddRequest,
  CredentialHistoryListResponse,
  CredentialHistoryDeleteRequest,
  CredentialHistoryDeleteResponse,
  SchemaFetchUrlRequest,
  SchemaFetchUrlResponse,
  CustomSchemaSaveRequest,
  CustomSchemaSaveResponse,
  CustomSchemaListResponse,
  CustomSchemaDeleteRequest,
  CustomSchemaDeleteResponse,
  SystemInfoResponse,
  LogTailResponse,
} from "../shared/ipc-types.js";
import { createLogger, getLogFilePath, readRecentLogs } from "./logger.js";
import { getStore, restrictStoreFilePermissions, CREDENTIAL_HISTORY_CAP } from "./store.js";
import type { CredentialHistoryEntry, CustomSchemaEntry } from "./store.js";
import { createSoftwareSigner, buildSigner } from "../signing/software-signer.js";
import type { PersistedSignerEntry } from "./persisted-signer-loader.js";
import { buildAndSign, listSchemas, getSchemaDefinition } from "../signing/local-signing-flow.js";

const logger = createLogger("ipc");
import { signWithFormat } from "../signing/proof-format-router.js";
import type { UiProofFormat } from "../shared/ipc-types.js";
import { generateKeyPairSync, createPublicKey, randomUUID, createHash } from "node:crypto";
import { packageCredential } from "../packaging/packager.js";
import type { PackageFormat } from "../packaging/packager.js";
import { parseCredentialJson } from "../packaging/json-export.js";
import {
  CryptoError,
  ValidationError,
  SchemaValidationError,
  buildPinnedFetchTarget,
  isPrivateIP,
  resolveAndPinHostname,
} from "@opencred/shared";
import { SchemaRegistry } from "@opencred/schema-engine";
import { packageCredential as packageCredentialWithTemplates } from "./credential-export.js";
import { queueRevocation, getQueueItems, publishPendingRevocations } from "./revocation-queue.js";
import { deriveVerificationMethod } from "../signing/types.js";
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
import {
  DeDiPublishManager,
  createPublishManager,
  CONTEXT_REGISTRY,
  SCHEMA_REGISTRY,
} from "@opencred/dedi-client";
import type { ContextRecord } from "@opencred/dedi-client";
import { generateInlineContext } from "@opencred/vc-core";

// ---------------------------------------------------------------------------
// In-memory registries
// ---------------------------------------------------------------------------

/** Maps key ID (did:key VM ID) -> key metadata for display. */
const importedKeys = new Map<string, KeyMetadata>();

/** Maps key ID -> Signer instance (private key stays in memory, never serialized). */
const loadedSigners = new Map<string, Signer>();

/** Maps key ID -> public key JWK (for DID document export in Self-Published Keys flow). */
const loadedPublicKeyJwks = new Map<string, Record<string, unknown>>();

/**
 * Merge signers reloaded from persisted paths into the in-memory registries.
 * Called once at startup from index.ts after reloadPersistedSigners().
 */
export function mergeReloadedSigners(
  result: import("./persisted-signer-loader.js").ReloadResult,
): void {
  for (const [id, meta] of result.metadata) {
    importedKeys.set(id, meta);
  }
  for (const [id, signer] of result.signers) {
    loadedSigners.set(id, signer);
  }
  if (result.metadata.size > 0) {
    logger.info("Merged reloaded signers", { count: result.metadata.size });
  }
}

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
    const { signer, format } = createSoftwareSigner(
      request.filePath,
      request.label,
      request.password,
    );

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
    logger.info("Key imported", {
      keyId: signer.id,
      fingerprint: meta.fingerprint,
      format,
      source: "file",
    });

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
      const savedPaths =
        (prefs["importedKeyPaths"] as Record<string, string | PersistedSignerEntry>) ?? {};
      savedPaths[signer.id] = { path: request.filePath, label: request.label };
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
    logger.error("Key import failed", { error: message });
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
    loadedPublicKeyJwks.set(signer.id, publicKey.export({ format: "jwk" }));

    logger.info("Key generated", { keyId: signer.id, fingerprint: meta.fingerprint });
    return { success: true, key: meta };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Key generation failed.";
    logger.error("Key generation failed", { error: message });
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

    // Extract issuer DID to determine the correct verificationMethod.
    // For did:web issuers, use the did:web verification method ID.
    const issuer = unsignedCredential.issuer;
    const issuerDid = typeof issuer === "string" ? issuer : issuer?.id;
    const verificationMethod = deriveVerificationMethod(issuerDid, signer.id);

    const { dataToSign, proofConfig } = await prepareProof(unsignedCredential, {
      verificationMethod,
      proofPurpose: "assertionMethod",
    });

    const signatureBytes = await signer.sign(dataToSign);
    const signedCredential = completeProof(unsignedCredential, proofConfig, signatureBytes);

    logger.info("Credential signed", { keyId: request.keyId });
    return {
      success: true,
      signedCredential: JSON.stringify(signedCredential),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Signing failed.";
    logger.error("Credential signing failed", { keyId: request.keyId, error: message });
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
      error:
        "Data Integrity proofs require ECDSA or EdDSA keys. Your key uses RSA — please select VC-JWT or SD-JWT-VC.",
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
        const credentialUuid = randomUUID();
        builder.setId(`urn:uuid:${credentialUuid}`);
        const revocationHash = createHash("sha256").update(credentialUuid).digest("hex");
        const statusListCredential = request.revocationRegistryUrl;
        const lookupUrl = statusListCredential.replace("/dedi/query/", "/dedi/lookup/");
        builder.setCredentialStatus({
          id: `${lookupUrl}/${revocationHash}`,
          type: "dedi",
          statusPurpose: "revocation",
          statusListCredential,
        });
      }

      // Look up the saved custom schema entry (if any) to fetch DeDi/context info.
      let customSchemaEntry: CustomSchemaEntry | undefined;
      if (request.schemaId?.startsWith("custom:")) {
        const store = getStore();
        const customSchemas =
          (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];
        customSchemaEntry = customSchemas.find((s) => s.id === request.schemaId);
      }

      // credentialSchema priority for inline/custom schemas:
      //   1. DeDi schema URL (if the schema was published to DeDi)
      //   2. user-provided URL (request.credentialSchemaUrl)
      //   3. inline data URI containing the base64-encoded JSON Schema
      //      (taken from the saved CustomSchemaEntry when available, or from
      //      the request payload otherwise)
      //
      // Per W3C VCDM 2.0 §4.10, every credential SHOULD reference the schema
      // it conforms to. The data-URI fallback ensures we always emit one even
      // when the issuer hasn't published anywhere yet.
      const credentialSchemaId = (() => {
        if (customSchemaEntry?.dediSchemaUrl) {
          return customSchemaEntry.dediSchemaUrl;
        }
        if (request.credentialSchemaUrl) {
          return request.credentialSchemaUrl;
        }
        // Pick the best schema object we have available for the data-URI
        // fallback. We prefer the persisted CustomSchemaEntry's schema (the
        // canonical, vetted form) and fall back to whatever the request
        // supplied. If the request only carried a sentinel value (e.g.
        // `inlineSchema: true` from older callers / tests), we fall back to
        // an empty object so the URI is still well-formed.
        const schemaObject =
          customSchemaEntry?.schema ??
          (typeof request.inlineSchema === "object" && request.inlineSchema !== null
            ? request.inlineSchema
            : {});
        const schemaJson = JSON.stringify(schemaObject);
        const base64 = Buffer.from(schemaJson, "utf8").toString("base64");
        return `data:application/schema+json;base64,${base64}`;
      })();
      builder.setSchema({ id: credentialSchemaId, type: "JsonSchema" });

      // Add JSON-LD context for Data Integrity proofs on inline/custom schemas
      if (proofFormat === "data-integrity") {
        if (request.contextUrl) {
          builder.addContext(request.contextUrl);
        } else if (request.inlineContext) {
          builder.addContext(request.inlineContext);
        } else if (customSchemaEntry?.dediContextUrl) {
          builder.addContext(customSchemaEntry.dediContextUrl);
        } else if (customSchemaEntry?.generatedContext) {
          builder.addContext(customSchemaEntry.generatedContext);
        }
      }

      const unsigned = builder.build();

      const vct = request.additionalTypes?.[0] ?? request.schemaId;

      // For did:web issuers, the verificationMethod must reference the
      // did:web DID's key, not the signer's internal did:key-based ID.
      const verificationMethod = deriveVerificationMethod(request.issuerDid, signer.id);

      // Custom JSON-LD contexts are served by the shared document loader
      // from a per-URL cache. The cache write path (handleCustomSchemaSave)
      // rejects conflicts on content hash, so canonicalization can rely on
      // the URL → document mapping being stable without per-call scoping.
      const result = await signWithFormat(signer, unsigned, proofFormat, {
        verificationMethod,
        selectiveDisclosureClaims: request.selectiveDisclosureClaims,
        vct,
      });
      signedCredentialJson = result.signedOutput;
      isCompactToken = result.isCompactToken;
    } else {
      // Look up custom schema context for Data Integrity proofs
      let contextUrl = request.contextUrl;
      let inlineContext = request.inlineContext;
      if (!contextUrl && !inlineContext && request.schemaId.startsWith("custom:")) {
        const store = getStore();
        const customSchemas =
          (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];
        const customSchema = customSchemas.find((s) => s.id === request.schemaId);
        if (customSchema?.dediContextUrl) {
          contextUrl = customSchema.dediContextUrl;
        } else if (customSchema?.generatedContext) {
          inlineContext = customSchema.generatedContext;
        }
      }

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
        contextUrl,
        inlineContext,
      });
      signedCredentialJson =
        typeof result.credential === "string"
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

    logger.info("Build and sign completed", {
      keyId: request.keyId,
      schemaId: request.schemaId,
      proofFormat,
    });

    // Record template usage for the "Recently used" list
    if (request.schemaId) {
      const schemaLabel = request.schemaId.startsWith("custom:")
        ? request.schemaId
        : request.schemaId;
      try {
        const def = getSchemaDefinition(request.schemaId);
        void handleRecentTemplatesRecord(null as unknown as IpcMainInvokeEvent, {
          schemaId: request.schemaId,
          schemaName: def.id,
        });
      } catch {
        void handleRecentTemplatesRecord(null as unknown as IpcMainInvokeEvent, {
          schemaId: request.schemaId,
          schemaName: schemaLabel,
        });
      }
    }

    // Fire-and-forget: publish schema to DeDi catalog if configured
    const dediMgr = getDeDiPublishManager();
    if (dediMgr && request.schemaId && !request.inlineSchema) {
      try {
        const def = getSchemaDefinition(request.schemaId);
        void dediMgr
          .ensureSchemaPublished({
            schemaId: def.id,
            version: "1",
            schema: def.schema,
            contextUrl: def.contextUrl,
            checksum: SchemaRegistry.computeChecksum(def.schema),
            publishedAt: new Date().toISOString(),
          })
          .then((r: import("@opencred/dedi-client").PublishResult | null) => {
            if (r) {
              const s = getStore();
              const pub = s.get("dediPublishedSchemas");
              const k = `${def.id}-v1`;
              if (!pub.includes(k)) s.set("dediPublishedSchemas", [...pub, k]);
            }
          })
          .catch(() => {
            /* fire-and-forget — errors logged by publish manager */
          });
      } catch {
        /* schema lookup failed — skip */
      }
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

    logger.error("Build and sign failed", { keyId: request.keyId, errorCode, error: message });
    return { success: false, error: message, errorCode, errorField };
  }
}

// ---------------------------------------------------------------------------
// Verification handler
// ---------------------------------------------------------------------------

/**
 * VERIFY_CREDENTIAL — verify a signed VC.
 *
 * Uses @opencred/verification with a composite DID resolver that supports
 * did:key, did:jwk, and did:web verification methods. Note: did:web
 * verification requires network access to fetch the DID document.
 */
async function handleVerifyCredential(
  _event: IpcMainInvokeEvent,
  request: VerifyCredentialRequest,
): Promise<VerifyCredentialResponse> {
  try {
    const parsed = JSON.parse(request.credential);

    // VC-JWT envelope detection: when the signed output is a JSON object with
    // { proof: { type: "JsonWebSignature2020", jwt: "eyJ..." } }, extract the
    // raw JWT string — the verification package expects the compact JWT, not
    // the JSON envelope.
    let verificationInput: Record<string, unknown> | string = parsed as Record<string, unknown>;
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      parsed.proof &&
      typeof parsed.proof === "object" &&
      typeof parsed.proof.jwt === "string"
    ) {
      verificationInput = parsed.proof.jwt;
    }

    // Resolve using composite DID resolver (supports did:key, did:jwk, did:web)
    const { DIDKeyResolver, DIDJwkResolver, DIDWebResolver, CompositeDIDResolver } =
      await import("@opencred/did");
    const { verifyCredential, loadCscaTrustStore } = await import("@opencred/verification");

    const compositeResolver = new CompositeDIDResolver(
      new Map([
        ["key", new DIDKeyResolver()],
        ["jwk", new DIDJwkResolver()],
        ["web", new DIDWebResolver()],
      ]),
    );

    // Custom JSON-LD contexts are served by the shared document loader
    // from a per-URL cache populated at schema-save time. Conflicts on the
    // same URL are rejected at save time by content-hash comparison, so
    // verification can rely on the URL → document mapping being stable.
    //
    // Load CSCA trust anchors when configured. Required for DSC-backed
    // credentials per nfh-trust-labs/opencred#316. The path is taken from
    // either the persisted preference or the CSCA_TRUST_STORE_PATH env var
    // (env wins). When unconfigured, credentials with an x5c chain will be
    // rejected with a fail-closed configuration error — this is intentional.
    const verifyStore = getStore();
    const verifyPrefs =
      (verifyStore.get("preferences" as keyof typeof verifyStore.store) as
        | Record<string, unknown>
        | undefined) ?? {};
    const cscaTrustStorePath =
      process.env.CSCA_TRUST_STORE_PATH ??
      (verifyPrefs["cscaTrustStorePath"] as string | undefined);
    const trustAnchors = cscaTrustStorePath
      ? await loadCscaTrustStore(cscaTrustStorePath, {
          onSkipped: ({ path: skippedPath, reason }) => {
            logger.warn("CSCA trust store entry skipped", { path: skippedPath, reason });
          },
        })
      : undefined;

    const verificationResult = await verifyCredential(verificationInput, {
      didResolver: compositeResolver,
      trustAnchors,
    });

    logger.info("Credential verified", {
      valid: verificationResult.verified,
      code: verificationResult.code,
    });
    return {
      success: true,
      valid: verificationResult.verified,
      message: verificationResult.verified
        ? "Credential signature is valid."
        : (verificationResult.checks.find((c) => !c.passed)?.detail ?? "Verification failed."),
      checks: verificationResult.checks,
    };
  } catch (err) {
    // Provide a user-friendly message for did:web offline failures
    const message = err instanceof Error ? err.message : "Verification failed.";
    const isNetworkError =
      message.includes("resolve hostname") || message.includes("Timeout fetching");
    const userMessage = isNetworkError
      ? "Verification requires network access to resolve the issuer's DID document (did:web). Please check your connection."
      : message;
    logger.error("Credential verification failed", { error: message });
    return { success: false, error: userMessage };
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
    const lineCount =
      request.csvContent.split(/\r?\n/).filter((l) => l.trim().length > 0).length - 1;
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

    logger.info("Batch started", {
      schemaId: request.schemaId,
      totalRows: parseResult.totalCount,
      validRows: parseResult.validCount,
    });
    void engine.start().then((finalProgress) => {
      batchState.results = finalProgress.rows;
      logger.info("Batch completed", {
        total: finalProgress.total,
        success: finalProgress.successCount,
        errors: finalProgress.errorCount,
      });
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
    logger.error("Batch start failed", { error: message });
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
    logger.info("PKCS#11 key connected", {
      keyId: signer.id,
      fingerprint: meta.fingerprint,
      slotIndex: request.slotIndex,
    });

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
    logger.error("PKCS#11 connect failed", { error: message });
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
    logger.info("OS certificate connected", {
      keyId: signer.id,
      fingerprint: meta.fingerprint,
      platform,
    });

    return {
      success: true,
      key: meta,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to connect OS certificate.";
    logger.error("OS certificate connect failed", { error: message });
    return { success: false, error: message };
  }
}

// ---------------------------------------------------------------------------
// Credential history handlers
// ---------------------------------------------------------------------------

/** CREDENTIAL_HISTORY_LIST — return all credential history entries. */
async function handleCredentialHistoryList(): Promise<CredentialHistoryListResponse> {
  const store = getStore();
  const history =
    (store.get("credentialHistory" as keyof typeof store.store) as CredentialHistoryEntry[]) ?? [];
  return { entries: history };
}

/** CREDENTIAL_HISTORY_ADD — add a credential to history (FIFO cap). */
async function handleCredentialHistoryAdd(
  _event: IpcMainInvokeEvent,
  request: CredentialHistoryAddRequest,
): Promise<CredentialHistoryEntry> {
  const store = getStore();
  const history =
    (store.get("credentialHistory" as keyof typeof store.store) as CredentialHistoryEntry[]) ?? [];

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
  const history =
    (store.get("credentialHistory" as keyof typeof store.store) as CredentialHistoryEntry[]) ?? [];
  const filtered = history.filter((e) => e.id !== request.id);
  const deleted = filtered.length < history.length;
  store.set("credentialHistory" as keyof typeof store.store, filtered);
  return { deleted };
}

// ---------------------------------------------------------------------------
// Custom schema handlers
// ---------------------------------------------------------------------------

/** CUSTOM_SCHEMA_LIST — return all custom schemas. */
// ---------------------------------------------------------------------------
// Schema URL fetch handler
// ---------------------------------------------------------------------------

/** Maximum response size accepted from a remote schema URL (1 MB). */
const SCHEMA_FETCH_MAX_BYTES = 1_048_576;

/** SCHEMA_FETCH_URL — fetch a JSON Schema from a remote URL. */
async function handleSchemaFetchUrl(
  _event: IpcMainInvokeEvent,
  request: SchemaFetchUrlRequest,
): Promise<SchemaFetchUrlResponse> {
  try {
    const { url } = request;
    if (!url.startsWith("https://")) {
      return { success: false, error: "URL must use HTTPS" };
    }

    // Validate the URL syntax up-front so we can fail fast on garbage input.
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      return { success: false, error: "Invalid URL" };
    }
    if (parsedUrl.protocol !== "https:") {
      return { success: false, error: "URL must use HTTPS" };
    }

    const hostname = parsedUrl.hostname;

    // SSRF + DNS rebinding (TOCTOU) protection: resolve the hostname
    // ourselves via dns.resolve4/resolve6 (NOT dns.lookup, which only
    // returns one address from getaddrinfo and can leave additional
    // records unchecked) and pin the resolved IP into the fetch URL so
    // the HTTP client cannot re-resolve the hostname between our check
    // and the network request.
    let fetchUrl: string;
    let hostHeader: string | undefined;
    if (isIP(hostname)) {
      if (isPrivateIP(hostname)) {
        return { success: false, error: "URL resolves to a private IP address" };
      }
      fetchUrl = url;
    } else {
      try {
        const pinned = await resolveAndPinHostname(hostname);
        const target = buildPinnedFetchTarget(url, pinned);
        fetchUrl = target.url;
        hostHeader = target.headers.Host;
      } catch (err) {
        const message = err instanceof Error ? err.message : "DNS lookup failed";
        if (message.includes("private/reserved")) {
          return { success: false, error: "URL resolves to a private IP address" };
        }
        // Sanitize the error returned to the renderer. The raw message from
        // resolveAndPinHostname includes the hostname (and can, via the
        // underlying dns errors, include the resolved IP), which would leak
        // internal-network-probing signal back to the caller. Log the
        // detailed error for ops triage, but return a generic message.
        logger.warn("Schema fetch DNS resolution failed", {
          url: request.url,
          error: message,
        });
        return { success: false, error: "DNS resolution failed" };
      }
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);

    let response: Response;
    try {
      const headers: Record<string, string> = { Accept: "application/json" };
      if (hostHeader) {
        headers.Host = hostHeader;
      }
      response = await fetch(fetchUrl, {
        signal: controller.signal,
        headers,
        redirect: "error",
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      return { success: false, error: `HTTP ${response.status}: ${response.statusText}` };
    }

    // Enforce a hard size cap on the response body. We check the
    // Content-Length header first as a fast path; even when the server
    // omits or lies about it, we read the body as a stream and abort
    // when SCHEMA_FETCH_MAX_BYTES is exceeded.
    const contentLength = response.headers.get("content-length");
    if (contentLength) {
      const declared = parseInt(contentLength, 10);
      if (Number.isFinite(declared) && declared > SCHEMA_FETCH_MAX_BYTES) {
        return {
          success: false,
          error: `Response too large (${String(declared)} bytes; limit ${String(SCHEMA_FETCH_MAX_BYTES)})`,
        };
      }
    }

    let bodyText: string;
    try {
      bodyText = await readBodyWithLimit(response, SCHEMA_FETCH_MAX_BYTES);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to read response body";
      return { success: false, error: message };
    }

    let body: unknown;
    try {
      body = JSON.parse(bodyText);
    } catch {
      return { success: false, error: "Response is not valid JSON" };
    }
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return { success: false, error: "Response is not a JSON object" };
    }

    const schema = body as Record<string, unknown>;
    if (
      !schema.properties ||
      typeof schema.properties !== "object" ||
      Array.isArray(schema.properties)
    ) {
      return {
        success: false,
        error: "Response does not appear to be a JSON Schema (missing 'properties' object)",
      };
    }

    const title = typeof schema.title === "string" ? schema.title : undefined;
    logger.info("Schema fetched from URL", {
      url,
      title,
      fieldCount: Object.keys(schema.properties as object).length,
    });
    return { success: true, schema, title };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    logger.warn("Schema fetch failed", { url: request.url, error: message });
    return { success: false, error: message };
  }
}

/**
 * Read a fetch Response body as text while enforcing a hard byte cap. The
 * stream is aborted (and the consumed bytes discarded) as soon as the limit
 * is exceeded so a hostile peer can never get us to allocate more than
 * `maxBytes` of memory for a single schema.
 */
async function readBodyWithLimit(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    // Streaming reader not available; fall back to text() but still cap.
    const text = await response.text();
    if (text.length > maxBytes) {
      throw new Error(`Response too large (limit ${String(maxBytes)} bytes)`);
    }
    return text;
  }

  const chunks: Uint8Array[] = [];
  let total = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      try {
        await reader.cancel();
      } catch {
        // Best-effort cancellation; the limit error below is the source of truth.
      }
      throw new Error(`Response too large (limit ${String(maxBytes)} bytes)`);
    }
    chunks.push(value);
  }

  // Concatenate chunks into a single Uint8Array, then decode as UTF-8.
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8").decode(merged);
}

// ---------------------------------------------------------------------------
// Custom schema handlers
// ---------------------------------------------------------------------------

/**
 * Result of fetching and validating a JSON-LD context document.
 * Either contains the parsed document or an error message — never both.
 */
interface ContextFetchResult {
  document?: Record<string, unknown>;
  error?: string;
}

/** Hard cap on context document size. 1 MiB is comfortably above any real
 * JSON-LD context (the W3C credentials/v2 context is ~16 KB) but small
 * enough that buffering it cannot exhaust main-process memory. */
const MAX_CONTEXT_BYTES = 1024 * 1024;

/** Hard cap on the entire fetch+read+parse pipeline. */
const CONTEXT_FETCH_TIMEOUT_MS = 10_000;

/** Internal sentinel — never propagated to the renderer. */
class ContextSizeLimitError extends Error {
  constructor() {
    super("context document exceeds size limit");
  }
}

/**
 * Fetch a JSON-LD context document for a user-provided URL.
 *
 * Threat model: the URL is pasted into the custom-schema setup form by the
 * user themselves. They have already chosen to trust it. The desktop main
 * process holds no privileged network position the user does not — it runs
 * with the user's network identity, on the user's machine, against the
 * user's chosen URL. SSRF gymnastics (DNS pinning, private-IP rejection)
 * are NOT applied here for that reason; they would be security theatre and
 * would block legitimate self-hosted issuers on private networks.
 *
 * What we DO enforce, because they protect the user from their own paste:
 *  - **HTTPS only.** No plaintext over hostile networks.
 *  - **No redirects.** A redirect could silently point at a different host.
 *  - **1 MiB body limit.** Real JSON-LD contexts are tens of kilobytes.
 *    A multi-megabyte body is either a misconfiguration or an attempt to
 *    OOM the main process (which would crash the entire app).
 *  - **10-second hard timeout** on the *entire* operation (fetch + body
 *    read + parse), so a slow-loris or hanging connection cannot freeze
 *    schema-save indefinitely.
 *  - **Strict shape validation.** The response must be a JSON object with
 *    a top-level `@context` key whose value is itself an object — i.e.
 *    a real JSON-LD context document, not arbitrary JSON.
 *  - **Generic errors to the renderer.** The error string returned to the
 *    renderer never reveals internal details (resolved hostnames, raw
 *    network errors, etc.). Full diagnostics go to the structured logger
 *    only — see `logger.warn` calls in this function.
 *
 * The response body is NEVER logged. Only structural diagnostics (success,
 * status code, byte count, key count) are emitted.
 */
async function fetchJsonLdContextDocument(url: string): Promise<ContextFetchResult> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { error: "Invalid context URL" };
  }

  if (parsed.protocol !== "https:") {
    return { error: "Context URL must use HTTPS" };
  }

  // Single AbortController gates the entire pipeline (fetch, body read,
  // parse). If the timeout fires mid-stream, getReader().read() rejects
  // and we surface a generic error.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CONTEXT_FETCH_TIMEOUT_MS);

  try {
    let response: Response;
    try {
      response = await fetch(url, {
        signal: controller.signal,
        headers: { Accept: "application/ld+json, application/json" },
        redirect: "error",
      });
    } catch (err) {
      logger.warn("Custom-schema context fetch failed", {
        url,
        error: err instanceof Error ? err.message : String(err),
      });
      return { error: "Failed to fetch context URL" };
    }

    if (!response.ok) {
      logger.warn("Custom-schema context fetch returned non-2xx", {
        url,
        status: response.status,
        statusText: response.statusText,
      });
      return { error: `Context fetch failed: HTTP ${response.status}` };
    }

    let bodyText: string;
    try {
      bodyText = await readBodyWithSizeLimit(response, MAX_CONTEXT_BYTES, controller.signal);
    } catch (err) {
      if (err instanceof ContextSizeLimitError) {
        logger.warn("Custom-schema context exceeds size limit", {
          url,
          limitBytes: MAX_CONTEXT_BYTES,
        });
        return {
          error: `Context document exceeds ${MAX_CONTEXT_BYTES}-byte size limit`,
        };
      }
      logger.warn("Custom-schema context body read failed", {
        url,
        error: err instanceof Error ? err.message : String(err),
      });
      return { error: "Failed to read context response body" };
    }

    let body: unknown;
    try {
      body = JSON.parse(bodyText);
    } catch (err) {
      logger.warn("Custom-schema context not valid JSON", {
        url,
        error: err instanceof Error ? err.message : String(err),
      });
      return { error: "Context response is not valid JSON" };
    }

    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return { error: "Context response is not a JSON object" };
    }

    // Strict shape: a real JSON-LD context document must have a top-level
    // `@context` key whose value is itself an object (the term map). We
    // do NOT accept "bare" context objects here because they are
    // ambiguous — accepting them would let an arbitrary JSON file pass
    // shape validation.
    const obj = body as Record<string, unknown>;
    const innerContext = obj["@context"];
    if (typeof innerContext !== "object" || innerContext === null || Array.isArray(innerContext)) {
      return {
        error: "Response does not look like a JSON-LD context document (missing @context object)",
      };
    }

    // Deliberately do NOT log the body — it may contain user-defined vocab.
    logger.info("Fetched JSON-LD context", {
      url,
      status: response.status,
      bytes: bodyText.length,
      contextKeyCount: Object.keys(innerContext as object).length,
    });

    return { document: obj };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Read a fetch Response body as UTF-8 text, aborting if it exceeds `limit`
 * bytes. Honours an external AbortSignal so the caller's timeout cancels
 * an in-flight read mid-stream.
 *
 * This streams via `body.getReader()` rather than calling `.text()` so we
 * never buffer more than `limit` bytes — a malicious or misconfigured
 * server cannot OOM the main process by sending a multi-gigabyte body.
 */
async function readBodyWithSizeLimit(
  response: Response,
  limit: number,
  signal: AbortSignal,
): Promise<string> {
  // Cheap pre-check: if Content-Length is set and honest, bail before reading.
  const declared = response.headers.get("content-length");
  if (declared) {
    const declaredBytes = Number(declared);
    if (Number.isFinite(declaredBytes) && declaredBytes > limit) {
      throw new ContextSizeLimitError();
    }
  }

  const body = response.body;
  if (!body) {
    // Some test/mock environments produce a Response with no streamable
    // body. Fall back to text() but enforce the limit on the result.
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > limit) {
      throw new ContextSizeLimitError();
    }
    return text;
  }

  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8");
  let accumulated = "";
  let receivedBytes = 0;

  try {
    let done = false;
    while (!done) {
      if (signal.aborted) {
        throw new Error("aborted");
      }
      const result = await reader.read();
      done = result.done;
      if (done) break;
      receivedBytes += result.value.byteLength;
      if (receivedBytes > limit) {
        throw new ContextSizeLimitError();
      }
      accumulated += decoder.decode(result.value, { stream: true });
    }
    accumulated += decoder.decode();
    return accumulated;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* ignore — reader may already be released */
    }
  }
}

async function handleCustomSchemaList(): Promise<CustomSchemaListResponse> {
  const store = getStore();
  const schemas =
    (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];
  return { schemas };
}

/** Build a response payload from a stored CustomSchemaEntry. */
function customSchemaSaveSuccess(entry: CustomSchemaEntry): CustomSchemaSaveResponse {
  return {
    id: entry.id,
    name: entry.name,
    schema: entry.schema,
    createdAt: entry.createdAt,
    success: true,
    ...(entry.sourceUrl ? { sourceUrl: entry.sourceUrl } : {}),
    ...(entry.dediContextUrl ? { contextUrl: entry.dediContextUrl } : {}),
    contextCached: entry.cachedContextDocument != null,
    ...(entry.cachedContextFetchedAt
      ? { cachedContextFetchedAt: entry.cachedContextFetchedAt }
      : {}),
  };
}

/**
 * Compute the canonical content hash of a fetched JSON-LD context document.
 * Two documents that serialise to the same JSON string hash to the same
 * value — good enough to detect conflicts where one URL is caching two
 * different bodies.
 */
function computeContextDocumentHash(document: Record<string, unknown>): string {
  return createHash("sha256").update(JSON.stringify(document)).digest("hex");
}

/**
 * Walk all stored custom schemas and return the first one (other than
 * `selfId`) whose `dediContextUrl` matches `url` AND whose stored
 * `cachedContextDocumentHash` differs from `newHash`. Entries with an
 * absent hash are treated as "match anything" so pre-existing data
 * written before the hash field was added does not trip the check —
 * the next time that legacy entry is re-saved it will acquire a hash
 * and start participating in conflict detection normally.
 */
function findContextHashConflict(
  schemas: readonly CustomSchemaEntry[],
  url: string,
  newHash: string,
  selfId: string | undefined,
): CustomSchemaEntry | undefined {
  for (const entry of schemas) {
    if (entry.id === selfId) continue;
    if (entry.dediContextUrl !== url) continue;
    // Legacy entries (written before the hash field existed) are treated
    // as matching — we cannot tell whether their document equals the new
    // one, and refusing the save would strand the user. See the field
    // doc in `store.ts` for rationale.
    if (entry.cachedContextDocumentHash == null) continue;
    if (entry.cachedContextDocumentHash !== newHash) {
      return entry;
    }
  }
  return undefined;
}

/**
 * CUSTOM_SCHEMA_SAVE — create or update a custom schema.
 *
 * If the request includes a JSON-LD context URL (or the schema gets a
 * `dediContextUrl` from DeDi publishing), the main process fetches that
 * URL once now and caches the document on the entry. Future signing /
 * verification can then resolve the URL locally without any network
 * requests, allowing strict canonicalization (`safe: true`) to succeed.
 *
 * SECURITY: the fetch is gated by `fetchJsonLdContextDocument`, which
 * enforces HTTPS-only, no redirects, a 1 MiB body cap, a 10-second
 * overall timeout, and strict JSON-LD shape validation. If the fetch
 * fails, the schema is still saved but the response carries an error so
 * the UI can surface "could not fetch context".
 *
 * Per JSON-LD 1.1 §3.1 a context URL is a global identifier — the same
 * URL must always resolve to the same document. If a previously-saved
 * schema already cached a different body under the same URL, this
 * handler refuses the save and returns a conflict error. This keeps the
 * shared URL → document cache consistent with the spec without needing
 * per-schema execution-context scoping around canonicalization.
 */
async function handleCustomSchemaSave(
  _event: IpcMainInvokeEvent,
  request: CustomSchemaSaveRequest,
): Promise<CustomSchemaSaveResponse> {
  const store = getStore();
  const schemas =
    (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];

  // Determine the context URL the user wants cached. If the request supplies
  // one explicitly, prefer it; otherwise we'll fall back to whatever URL DeDi
  // publishing produces below (dediContextUrl).
  const userContextUrl = request.contextUrl?.trim() || undefined;

  if (request.id) {
    // Update existing — preserve immutable fields, refresh name/schema and
    // optionally re-fetch the cached context document if a context URL is
    // present and not yet cached.
    const idx = schemas.findIndex((s) => s.id === request.id);
    if (idx >= 0) {
      const existing = schemas[idx];
      const updated: CustomSchemaEntry = {
        ...existing,
        name: request.name,
        schema: request.schema,
      };
      if (userContextUrl) {
        updated.dediContextUrl = userContextUrl;
      }

      let fetchError: string | undefined;
      const targetContextUrl = updated.dediContextUrl;
      if (targetContextUrl && !updated.cachedContextDocument) {
        const result = await fetchJsonLdContextDocument(targetContextUrl);
        if (result.document) {
          const newHash = computeContextDocumentHash(result.document);
          const conflict = findContextHashConflict(schemas, targetContextUrl, newHash, updated.id);
          if (conflict) {
            logger.warn("Custom schema context hash conflict (update)", {
              schemaId: updated.id,
              conflictingSchemaId: conflict.id,
              url: targetContextUrl,
            });
            const response = customSchemaSaveSuccess(updated);
            response.contextCached = false;
            response.error =
              `Context URL ${targetContextUrl} is already cached with a ` +
              `different content hash by schema '${conflict.name}'. ` +
              `Refusing to overwrite — JSON-LD context URLs must be global.`;
            return response;
          }
          updated.cachedContextDocument = result.document;
          updated.cachedContextDocumentHash = newHash;
          updated.cachedContextFetchedAt = new Date().toISOString();
        } else {
          fetchError = result.error;
          logger.warn("Custom schema context fetch failed (update)", {
            schemaId: updated.id,
            error: fetchError,
          });
        }
      }

      schemas[idx] = updated;
      store.set("customSchemas" as keyof typeof store.store, schemas);
      const response = customSchemaSaveSuccess(updated);
      if (fetchError) {
        response.error = fetchError;
      }
      return response;
    }
  }

  // Create new
  const entry: CustomSchemaEntry = {
    id: `custom:${randomUUID()}`,
    name: request.name,
    schema: request.schema,
    createdAt: new Date().toISOString(),
    ...(request.sourceUrl ? { sourceUrl: request.sourceUrl } : {}),
    ...(userContextUrl ? { dediContextUrl: userContextUrl } : {}),
  };

  // Auto-generate JSON-LD context from schema
  const namespaceUri = `urn:opencred:vocab:${entry.id}:`;
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- JsonSchema is not exported; schema shape is validated at input
    entry.generatedContext = generateInlineContext(request.schema as any, namespaceUri);
  } catch (err) {
    logger.warn("Failed to generate inline context for custom schema (non-fatal)", {
      schemaId: entry.id,
      error: err instanceof Error ? err.message : String(err),
    });
  }

  // Publish to DeDi if configured
  const dediConfig = store.get("dediConfig");
  if (dediConfig) {
    const mgr = getDeDiPublishManager();
    if (mgr) {
      const version = "1.0.0";
      const schemaRecordName = `${entry.id}-v${version}`;
      const contextRecordName = `${entry.id}-ctx-v${version}`;

      // Publish schema (fire-and-forget)
      mgr
        .ensureSchemaPublished({
          schemaId: entry.id,
          version,
          schema: request.schema,
          checksum: SchemaRegistry.computeChecksum(request.schema),
          publishedAt: new Date().toISOString(),
        })
        .catch(() => {
          /* logged internally */
        });

      // Publish context (fire-and-forget)
      if (entry.generatedContext) {
        const contextRecord: ContextRecord = {
          schemaId: entry.id,
          version,
          context: entry.generatedContext,
          publishedAt: new Date().toISOString(),
        };
        mgr.publishContext(contextRecord).catch(() => {
          /* logged internally */
        });
      }

      entry.dediSchemaUrl = `${dediConfig.baseUrl}/dedi/lookup/${dediConfig.namespace}/${SCHEMA_REGISTRY}/${schemaRecordName}`;
      // Only overwrite the user-provided context URL if none was supplied.
      if (!entry.dediContextUrl) {
        entry.dediContextUrl = `${dediConfig.baseUrl}/dedi/lookup/${dediConfig.namespace}/${CONTEXT_REGISTRY}/${contextRecordName}`;
      }
    }
  }

  // Fetch and cache the context document if a URL is present.
  let fetchError: string | undefined;
  if (entry.dediContextUrl && !entry.cachedContextDocument) {
    const result = await fetchJsonLdContextDocument(entry.dediContextUrl);
    if (result.document) {
      const newHash = computeContextDocumentHash(result.document);
      const conflict = findContextHashConflict(schemas, entry.dediContextUrl, newHash, entry.id);
      if (conflict) {
        logger.warn("Custom schema context hash conflict (create)", {
          schemaId: entry.id,
          conflictingSchemaId: conflict.id,
          url: entry.dediContextUrl,
        });
        // Refuse the save entirely — we don't want to persist a schema
        // with an unresolvable context. The response mirrors other
        // "fetch failed" outcomes so the UI renders a consistent shape.
        const response = customSchemaSaveSuccess(entry);
        response.contextCached = false;
        response.error =
          `Context URL ${entry.dediContextUrl} is already cached with a ` +
          `different content hash by schema '${conflict.name}'. ` +
          `Refusing to overwrite — JSON-LD context URLs must be global.`;
        return response;
      }
      entry.cachedContextDocument = result.document;
      entry.cachedContextDocumentHash = newHash;
      entry.cachedContextFetchedAt = new Date().toISOString();
    } else {
      fetchError = result.error;
      logger.warn("Custom schema context fetch failed (create)", {
        schemaId: entry.id,
        error: fetchError,
      });
    }
  }

  store.set("customSchemas" as keyof typeof store.store, [...schemas, entry]);

  const response = customSchemaSaveSuccess(entry);
  if (fetchError) {
    response.error = fetchError;
  }
  return response;
}

/** CUSTOM_SCHEMA_DELETE — remove a custom schema. */
async function handleCustomSchemaDelete(
  _event: IpcMainInvokeEvent,
  request: CustomSchemaDeleteRequest,
): Promise<CustomSchemaDeleteResponse> {
  const store = getStore();
  const schemas =
    (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];
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
// Self-Published Keys (did:web)
// ---------------------------------------------------------------------------

import { exportDidDocument } from "./did-web-export.js";
import { DIDWebResolver, encodeDidWeb } from "@opencred/did";
import type {
  DidWebExportRequest,
  DidWebExportResponse,
  DidWebVerifyRequest,
  DidWebVerifyResponse,
  DeDiConfigSetRequest,
  DeDiConfigSetResponse,
  DeDiStatusResponse,
  DeDiPublishDIDRequest,
  DeDiPublishSchemaRequest,
  DeDiPublishResponse,
  DeDiEnsureRegistriesResponse,
} from "../shared/ipc-types.js";

async function handleDidWebExport(
  _event: IpcMainInvokeEvent,
  request: DidWebExportRequest,
): Promise<DidWebExportResponse> {
  try {
    const jwk = loadedPublicKeyJwks.get(request.keyId);
    if (!jwk) return { success: false, error: "Key not found or not a generated key" };
    const did = encodeDidWeb(request.domain);
    const didDocument = exportDidDocument(jwk as import("@opencred/did").JWK, request.domain);
    return { success: true, didDocument, did };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : "DID document export failed.",
    };
  }
}

const DOMAIN_PATTERN = /^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}(:\d+)?$/;

async function handleDidWebVerify(
  _event: IpcMainInvokeEvent,
  request: DidWebVerifyRequest,
): Promise<DidWebVerifyResponse> {
  if (!request.domain || !DOMAIN_PATTERN.test(request.domain)) {
    return { success: true, accessible: false, error: "Invalid domain format" };
  }
  try {
    const resolver = new DIDWebResolver();
    await resolver.resolve(encodeDidWeb(request.domain));
    return { success: true, accessible: true };
  } catch (err) {
    return {
      success: true,
      accessible: false,
      error: err instanceof Error ? err.message : "DID verification failed.",
    };
  }
}

// ---------------------------------------------------------------------------
// DeDi integration
// ---------------------------------------------------------------------------

let publishManager: DeDiPublishManager | null = null;

export function getDeDiPublishManager(): DeDiPublishManager | null {
  if (publishManager) return publishManager;
  const store = getStore();
  const config = store.get("dediConfig");
  if (!config) return null;
  const credJson = getDeDiCredentialFromKeychain();
  if (!credJson) return null;
  let parsed: { apiKey?: string; email?: string; password?: string };
  try {
    parsed = JSON.parse(credJson);
  } catch {
    return null;
  }
  const auth =
    config.authType === "api-key"
      ? { type: "api-key" as const, apiKey: parsed.apiKey ?? "" }
      : { type: "bearer" as const, email: parsed.email ?? "", password: parsed.password ?? "" };
  publishManager = createPublishManager(
    {
      baseUrl: config.baseUrl,
      defaultNamespace: config.namespace,
      auth,
      timeoutMs: 10_000,
      circuitBreakerThreshold: 5,
      maxRetries: 3,
      logger,
    },
    store.get("dediPublishedSchemas"),
    logger,
  );
  return publishManager;
}

function getDeDiCredentialFromKeychain(): string | null {
  if (!safeStorage.isEncryptionAvailable()) return null;
  const encrypted = getStore().get("preferences")["dediCredentialEncrypted"] as string | undefined;
  if (!encrypted) return null;
  try {
    return safeStorage.decryptString(Buffer.from(encrypted, "base64"));
  } catch {
    return null;
  }
}

function storeDeDiCredentialInKeychain(json: string): void {
  if (!safeStorage.isEncryptionAvailable()) throw new Error("OS encryption unavailable");
  const enc = safeStorage.encryptString(json).toString("base64");
  const store = getStore();
  store.set("preferences", { ...store.get("preferences"), dediCredentialEncrypted: enc });
}

async function handleDeDiSetConfig(
  _event: IpcMainInvokeEvent,
  request: DeDiConfigSetRequest,
): Promise<DeDiConfigSetResponse> {
  try {
    const store = getStore();
    store.set("dediConfig", {
      baseUrl: request.baseUrl,
      namespace: request.namespace,
      authType: request.credentials.type,
    });
    const cred =
      request.credentials.type === "api-key"
        ? { apiKey: request.credentials.apiKey }
        : { email: request.credentials.email, password: request.credentials.password };
    storeDeDiCredentialInKeychain(JSON.stringify(cred));
    publishManager = null;
    const mgr = getDeDiPublishManager();
    if (!mgr) {
      logger.error("DeDi publish manager could not be created");
      return { success: true, registriesReady: false };
    }
    let registriesReady = false;
    try {
      registriesReady = await mgr.ensureRegistries(request.namespace);
    } catch (regErr) {
      logger.error("DeDi ensureRegistries failed", {
        error: regErr instanceof Error ? regErr.message : String(regErr),
      });
    }
    store.set("dediRegistriesReady", registriesReady);
    return { success: true, registriesReady };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : "Failed to configure DeDi",
    };
  }
}

async function handleDeDiGetStatus(_event: IpcMainInvokeEvent): Promise<DeDiStatusResponse> {
  const store = getStore();
  const config = store.get("dediConfig");
  return {
    configured: config != null,
    namespace: config?.namespace,
    registriesReady: store.get("dediRegistriesReady") === true,
    publishedSchemas: store.get("dediPublishedSchemas"),
  };
}

async function handleDeDiPublishDID(
  _event: IpcMainInvokeEvent,
  request: DeDiPublishDIDRequest,
): Promise<DeDiPublishResponse> {
  const mgr = getDeDiPublishManager();
  if (!mgr) return { success: false, error: "DeDi not configured" };
  const result = await mgr.publishDIDDocument(request.did, request.document);
  return result
    ? { success: true, recordName: result.recordName }
    : { success: false, error: "Failed to publish DID to DeDi" };
}

async function handleDeDiPublishSchema(
  _event: IpcMainInvokeEvent,
  request: DeDiPublishSchemaRequest,
): Promise<DeDiPublishResponse> {
  const mgr = getDeDiPublishManager();
  if (!mgr) return { success: false, error: "DeDi not configured" };

  try {
    const def = getSchemaDefinition(request.schemaId);
    const result = await mgr.ensureSchemaPublished({
      schemaId: def.id,
      version: "1",
      schema: def.schema,
      contextUrl: def.contextUrl,
      checksum: SchemaRegistry.computeChecksum(def.schema),
      publishedAt: new Date().toISOString(),
    });

    if (result) {
      const s = getStore();
      const pub = s.get("dediPublishedSchemas");
      const k = `${def.id}-v1`;
      if (!pub.includes(k)) s.set("dediPublishedSchemas", [...pub, k]);
      return { success: true, recordName: result.recordName };
    }
    // Already published (idempotent)
    return { success: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Schema publication failed";
    logger.error("DeDi schema publication failed", { schemaId: request.schemaId, error: message });
    return { success: false, error: message };
  }
}

async function handleDeDiEnsureRegistries(
  _event: IpcMainInvokeEvent,
): Promise<DeDiEnsureRegistriesResponse> {
  const mgr = getDeDiPublishManager();
  if (!mgr) return { success: false, error: "DeDi not configured" };
  const store = getStore();
  const ns = store.get("dediConfig")?.namespace;
  if (!ns) return { success: false, error: "DeDi not configured" };
  const ok = await mgr.ensureRegistries(ns);
  store.set("dediRegistriesReady", ok);
  return ok ? { success: true } : { success: false, error: "Failed to create DeDi registries" };
}

/**
 * Disconnect DeDi integration — clears stored config, removes the encrypted
 * credential from preferences, and resets the publish manager.
 *
 * SECURITY NOTE: This is an intentional credential deletion operation invoked
 * by the user via the Settings UI to disconnect their DeDi account.
 */
async function handleDeDiDisconnect(
  _event: IpcMainInvokeEvent,
): Promise<import("../shared/ipc-types.js").DeDiDisconnectResponse> {
  const store = getStore();
  store.delete("dediConfig" as never);
  store.set("dediPublishedSchemas", []);
  store.delete("dediRegistriesReady" as never);
  const prefs = store.get("preferences");
  if (prefs && typeof prefs === "object" && "dediCredentialEncrypted" in prefs) {
    const rest = { ...(prefs as Record<string, unknown>) };
    delete rest.dediCredentialEncrypted;
    store.set("preferences", rest as never);
  }
  publishManager = null;
  return { success: true };
}

// ---------------------------------------------------------------------------
// Recent templates
// ---------------------------------------------------------------------------

import type {
  RecentTemplatesListResponse,
  RecentTemplateRecordRequest,
} from "../shared/ipc-types.js";
import { RECENT_TEMPLATES_CAP } from "./store.js";
import type { RecentTemplateEntry } from "./store.js";

async function handleRecentTemplatesList(
  _event: IpcMainInvokeEvent,
): Promise<RecentTemplatesListResponse> {
  const store = getStore();
  const templates = store.get("recentTemplates");
  return { templates };
}

async function handleRecentTemplatesRecord(
  _event: IpcMainInvokeEvent,
  request: RecentTemplateRecordRequest,
): Promise<void> {
  const store = getStore();
  const templates = store.get("recentTemplates");
  const existing = templates.find((t: RecentTemplateEntry) => t.schemaId === request.schemaId);
  if (existing) {
    existing.lastUsedAt = new Date().toISOString();
    existing.useCount += 1;
    existing.schemaName = request.schemaName;
  } else {
    templates.unshift({
      schemaId: request.schemaId,
      schemaName: request.schemaName,
      lastUsedAt: new Date().toISOString(),
      useCount: 1,
    });
  }
  // Sort by lastUsedAt descending, cap at limit
  templates.sort((a: RecentTemplateEntry, b: RecentTemplateEntry) =>
    b.lastUsedAt.localeCompare(a.lastUsedAt),
  );
  store.set("recentTemplates", templates.slice(0, RECENT_TEMPLATES_CAP));
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

  // Self-Published Keys (did:web)
  ipcMain.handle(IPC_CHANNELS.DID_WEB_EXPORT, handleDidWebExport);
  ipcMain.handle(IPC_CHANNELS.DID_WEB_VERIFY, handleDidWebVerify);

  // DeDi integration
  ipcMain.handle(IPC_CHANNELS.DEDI_SET_CONFIG, handleDeDiSetConfig);
  ipcMain.handle(IPC_CHANNELS.DEDI_GET_STATUS, handleDeDiGetStatus);
  ipcMain.handle(IPC_CHANNELS.DEDI_PUBLISH_DID, handleDeDiPublishDID);
  ipcMain.handle(IPC_CHANNELS.DEDI_PUBLISH_SCHEMA, handleDeDiPublishSchema);
  ipcMain.handle(IPC_CHANNELS.DEDI_ENSURE_REGISTRIES, handleDeDiEnsureRegistries);
  ipcMain.handle(IPC_CHANNELS.DEDI_DISCONNECT, handleDeDiDisconnect);

  // Recent templates
  ipcMain.handle(IPC_CHANNELS.RECENT_TEMPLATES_LIST, handleRecentTemplatesList);
  ipcMain.handle(IPC_CHANNELS.RECENT_TEMPLATES_RECORD, handleRecentTemplatesRecord);

  // Credential history (deprecated)
  ipcMain.handle(IPC_CHANNELS.CREDENTIAL_HISTORY_LIST, handleCredentialHistoryList);
  ipcMain.handle(IPC_CHANNELS.CREDENTIAL_HISTORY_ADD, handleCredentialHistoryAdd);
  ipcMain.handle(IPC_CHANNELS.CREDENTIAL_HISTORY_DELETE, handleCredentialHistoryDelete);

  // Schema URL fetch
  ipcMain.handle(IPC_CHANNELS.SCHEMA_FETCH_URL, handleSchemaFetchUrl);

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
