/**
 * Tests for the preload API type safety.
 *
 * Verifies that the OpenCredDesktopAPI interface matches the IPC_CHANNELS
 * definition — every channel should have a corresponding method in the
 * preload API, and the method signatures should match the expected types.
 */

import { describe, it, expect } from "vitest";
import { IPC_CHANNELS } from "../shared/ipc-channels";
import type { OpenCredDesktopAPI } from "../shared/ipc-types";

/**
 * Mapping from IPC channel constants to the expected method paths on
 * OpenCredDesktopAPI. Top-level methods use simple names.
 */
const CHANNEL_TO_METHOD: Record<string, string> = {
  [IPC_CHANNELS.KEY_IMPORT]: "importKey",
  [IPC_CHANNELS.KEY_LIST]: "listKeys",
  [IPC_CHANNELS.KEY_GENERATE]: "generateKey",
  [IPC_CHANNELS.SCHEMA_LIST]: "listSchemas",
  [IPC_CHANNELS.SCHEMA_GET]: "getSchema",
  [IPC_CHANNELS.SIGN_CREDENTIAL]: "signCredential",
  [IPC_CHANNELS.BUILD_AND_SIGN]: "buildAndSign",
  [IPC_CHANNELS.VERIFY_CREDENTIAL]: "verifyCredential",
  [IPC_CHANNELS.PACKAGE_CREDENTIAL]: "packageCredential",
  [IPC_CHANNELS.REVOCATION_QUEUE]: "queueRevocation",
  [IPC_CHANNELS.REVOCATION_STATUS]: "getRevocationStatus",
  [IPC_CHANNELS.REVOCATION_PUBLISH]: "publishRevocations",
  [IPC_CHANNELS.BATCH_START]: "batchStart",
  [IPC_CHANNELS.BATCH_STATUS]: "batchStatus",
  [IPC_CHANNELS.BATCH_CANCEL]: "batchCancel",
  [IPC_CHANNELS.BATCH_EXPORT]: "batchExport",
  [IPC_CHANNELS.FILE_OPEN]: "openFile",
  [IPC_CHANNELS.FILE_SAVE]: "saveFile",
  [IPC_CHANNELS.GET_OFFLINE_STATUS]: "getOfflineStatus",
  [IPC_CHANNELS.PKCS11_DETECT]: "pkcs11Detect",
  [IPC_CHANNELS.PKCS11_LIST_SLOTS]: "pkcs11ListSlots",
  [IPC_CHANNELS.PKCS11_LIST_KEYS]: "pkcs11ListKeys",
  [IPC_CHANNELS.PKCS11_CONNECT]: "pkcs11Connect",
  [IPC_CHANNELS.UPDATE_CHECK]: "updateCheck",
  [IPC_CHANNELS.UPDATE_DOWNLOAD]: "updateDownload",
  [IPC_CHANNELS.UPDATE_INSTALL]: "updateInstall",
  [IPC_CHANNELS.UPDATE_STATUS]: "updateGetStatus",
  [IPC_CHANNELS.OSCERT_LIST]: "osCertList",
  [IPC_CHANNELS.OSCERT_SIGN]: "osCertSign",
  [IPC_CHANNELS.OSCERT_CONNECT]: "osCertConnect",
  [IPC_CHANNELS.DID_WEB_EXPORT]: "exportDidDocument",
  [IPC_CHANNELS.DID_WEB_VERIFY]: "verifyDidWeb",
  [IPC_CHANNELS.CREDENTIAL_HISTORY_LIST]: "credentialHistoryList",
  [IPC_CHANNELS.CREDENTIAL_HISTORY_ADD]: "credentialHistoryAdd",
  [IPC_CHANNELS.CREDENTIAL_HISTORY_DELETE]: "credentialHistoryDelete",
  [IPC_CHANNELS.CUSTOM_SCHEMA_SAVE]: "customSchemaSave",
  [IPC_CHANNELS.CUSTOM_SCHEMA_LIST]: "customSchemaList",
  [IPC_CHANNELS.CUSTOM_SCHEMA_DELETE]: "customSchemaDelete",
  [IPC_CHANNELS.SYSTEM_INFO]: "getSystemInfo",
  [IPC_CHANNELS.LOG_TAIL]: "getRecentLogs",
  [IPC_CHANNELS.DEDI_SET_CONFIG]: "dediSetConfig",
  [IPC_CHANNELS.DEDI_GET_STATUS]: "dediGetStatus",
  [IPC_CHANNELS.DEDI_PUBLISH_DID]: "dediPublishDid",
  [IPC_CHANNELS.DEDI_PUBLISH_SCHEMA]: "dediPublishSchema",
  [IPC_CHANNELS.DEDI_ENSURE_REGISTRIES]: "dediEnsureRegistries",
  [IPC_CHANNELS.DEDI_DISCONNECT]: "dediDisconnect",
  [IPC_CHANNELS.RECENT_TEMPLATES_LIST]: "recentTemplatesList",
  [IPC_CHANNELS.RECENT_TEMPLATES_RECORD]: "recentTemplatesRecord",
  [IPC_CHANNELS.SCHEMA_FETCH_URL]: "schemaFetchUrl",
  [IPC_CHANNELS.GET_CONFIG]: "getConfig",
  [IPC_CHANNELS.SET_CONFIG]: "setConfig",
  [IPC_CHANNELS.BRANDING_GET]: "brandingGet",
  [IPC_CHANNELS.BRANDING_SET]: "brandingSet",
  [IPC_CHANNELS.BRANDING_CLEAR]: "brandingClear",
};

/**
 * Resolve a dot-notation path on an object.
 */
function resolvePath(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

describe("Preload API completeness", () => {
  it("should have a method for every IPC channel", () => {
    const channelValues = Object.values(IPC_CHANNELS);
    const mappedChannels = Object.keys(CHANNEL_TO_METHOD);

    // Every channel value should appear in the mapping.
    for (const channel of channelValues) {
      expect(mappedChannels).toContain(channel);
    }
  });

  it("should have exactly one API method per IPC channel", () => {
    const channelCount = Object.keys(IPC_CHANNELS).length;
    const mappingCount = Object.keys(CHANNEL_TO_METHOD).length;
    expect(mappingCount).toBe(channelCount);
  });

  it("should have unique method paths (no two channels map to the same method)", () => {
    const methods = Object.values(CHANNEL_TO_METHOD);
    const uniqueMethods = new Set(methods);
    expect(uniqueMethods.size).toBe(methods.length);
  });

  it("should have all mapped methods present on a conforming API object", () => {
    // Create a minimal mock that satisfies OpenCredDesktopAPI.
    const api: OpenCredDesktopAPI = {
      importKey: async () => ({ success: true }),
      listKeys: async () => ({ keys: [] }),
      generateKey: async () => ({ success: true }),
      listSchemas: async () => ({ schemas: [] }),
      getSchema: async () => ({ id: "test", schema: {} }),
      signCredential: async () => ({ success: false, error: "stub" }),
      buildAndSign: async () => ({ success: false, error: "stub" }),
      verifyCredential: async () => ({ success: true, valid: true }),
      packageCredential: async () => ({ success: true }),
      queueRevocation: async () => ({ success: true }),
      getRevocationStatus: async () => ({ items: [] }),
      publishRevocations: async (_req) => ({ results: [] }),
      batchStart: async () => ({ success: true }),
      batchStatus: async () => ({
        total: 0,
        completed: 0,
        successCount: 0,
        errorCount: 0,
        skippedCount: 0,
        running: false,
        cancelled: false,
        rows: [],
      }),
      batchCancel: async () => ({ success: true }),
      batchExport: async () => ({ success: true }),
      openFile: async () => ({ content: null, filePath: null }),
      saveFile: async () => ({ filePath: null }),
      pkcs11Detect: async () => ({ exists: false }),
      pkcs11ListSlots: async () => ({ success: true, slots: [] }),
      pkcs11ListKeys: async () => ({ success: true, keys: [] }),
      pkcs11Connect: async () => ({ success: false, error: "stub" }),
      osCertList: async () => ({ success: true }),
      osCertSign: async () => ({ success: false, error: "stub" }),
      osCertConnect: async () => ({ success: false, error: "stub" }),
      getOfflineStatus: async () => false,
      updateCheck: async () => ({
        checking: false,
        available: false,
        downloading: false,
        downloaded: false,
      }),
      updateDownload: async () => ({
        checking: false,
        available: false,
        downloading: false,
        downloaded: false,
      }),
      updateInstall: async () => {},
      updateGetStatus: async () => ({
        checking: false,
        available: false,
        downloading: false,
        downloaded: false,
      }),
      exportDidDocument: async () => ({ success: true }),
      verifyDidWeb: async () => ({ success: true, accessible: true }),
      onUpdateStatus: () => () => {},
      credentialHistoryList: async () => ({ entries: [] }),
      credentialHistoryAdd: async (req: Parameters<OpenCredDesktopAPI["credentialHistoryAdd"]>[0]) => ({ ...req, id: "test", issuedAt: "2025-01-01T00:00:00Z" }),
      credentialHistoryDelete: async () => ({ deleted: true }),
      schemaFetchUrl: async () => ({ success: true }),
      customSchemaList: async () => ({ schemas: [] }),
      customSchemaSave: async () => ({ id: "test", name: "test", schema: {}, createdAt: "2025-01-01T00:00:00Z" }),
      customSchemaDelete: async () => ({ deleted: true }),
      getSystemInfo: async () => ({ version: "test" }),
      getRecentLogs: async () => ({ logs: [], logPath: "" }),
      dediSetConfig: async () => {},
      dediGetStatus: async () => ({ configured: false }),
      dediPublishDid: async () => ({ success: true }),
      dediPublishSchema: async () => ({ success: true }),
      dediEnsureRegistries: async () => ({ success: true }),
      dediDisconnect: async () => ({ success: true }),
      recentTemplatesList: async () => ({ templates: [] }),
      recentTemplatesRecord: async () => {},
      getConfig: async () => undefined,
      setConfig: async () => {},
      brandingGet: async () => ({ configured: false }),
      brandingSet: async () => ({ success: true }),
      brandingClear: async () => ({ success: true }),
    };

    for (const methodPath of Object.values(CHANNEL_TO_METHOD)) {
      const resolved = resolvePath(api as unknown as Record<string, unknown>, methodPath);
      expect(typeof resolved).toBe("function");
    }
  });

  it("should have all API methods return promises", async () => {
    const api: OpenCredDesktopAPI = {
      importKey: async () => ({ success: true }),
      listKeys: async () => ({ keys: [] }),
      generateKey: async () => ({ success: true }),
      listSchemas: async () => ({ schemas: [] }),
      getSchema: async () => ({ id: "test", schema: {} }),
      signCredential: async () => ({ success: false, error: "stub" }),
      buildAndSign: async () => ({ success: false, error: "stub" }),
      verifyCredential: async () => ({ success: true, valid: true }),
      packageCredential: async () => ({ success: true }),
      queueRevocation: async () => ({ success: true }),
      getRevocationStatus: async () => ({ items: [] }),
      publishRevocations: async (_req) => ({ results: [] }),
      batchStart: async () => ({ success: true }),
      batchStatus: async () => ({
        total: 0,
        completed: 0,
        successCount: 0,
        errorCount: 0,
        skippedCount: 0,
        running: false,
        cancelled: false,
        rows: [],
      }),
      batchCancel: async () => ({ success: true }),
      batchExport: async () => ({ success: true }),
      openFile: async () => ({ content: null, filePath: null }),
      saveFile: async () => ({ filePath: null }),
      pkcs11Detect: async () => ({ exists: false }),
      pkcs11ListSlots: async () => ({ success: true, slots: [] }),
      pkcs11ListKeys: async () => ({ success: true, keys: [] }),
      pkcs11Connect: async () => ({ success: false, error: "stub" }),
      osCertList: async () => ({ success: true }),
      osCertSign: async () => ({ success: false, error: "stub" }),
      osCertConnect: async () => ({ success: false, error: "stub" }),
      getOfflineStatus: async () => false,
      updateCheck: async () => ({
        checking: false,
        available: false,
        downloading: false,
        downloaded: false,
      }),
      updateDownload: async () => ({
        checking: false,
        available: false,
        downloading: false,
        downloaded: false,
      }),
      updateInstall: async () => {},
      updateGetStatus: async () => ({
        checking: false,
        available: false,
        downloading: false,
        downloaded: false,
      }),
      exportDidDocument: async () => ({ success: true }),
      verifyDidWeb: async () => ({ success: true, accessible: true }),
      onUpdateStatus: () => () => {},
      credentialHistoryList: async () => ({ entries: [] }),
      credentialHistoryAdd: async (req: Parameters<OpenCredDesktopAPI["credentialHistoryAdd"]>[0]) => ({ ...req, id: "test", issuedAt: "2025-01-01T00:00:00Z" }),
      credentialHistoryDelete: async () => ({ deleted: true }),
      schemaFetchUrl: async () => ({ success: true }),
      customSchemaList: async () => ({ schemas: [] }),
      customSchemaSave: async () => ({ id: "test", name: "test", schema: {}, createdAt: "2025-01-01T00:00:00Z" }),
      customSchemaDelete: async () => ({ deleted: true }),
      getSystemInfo: async () => ({ version: "test" }),
      getRecentLogs: async () => ({ logs: [], logPath: "" }),
      dediSetConfig: async () => {},
      dediGetStatus: async () => ({ configured: false }),
      dediPublishDid: async () => ({ success: true }),
      dediPublishSchema: async () => ({ success: true }),
      dediEnsureRegistries: async () => ({ success: true }),
      dediDisconnect: async () => ({ success: true }),
      recentTemplatesList: async () => ({ templates: [] }),
      recentTemplatesRecord: async () => {},
      getConfig: async () => undefined,
      setConfig: async () => {},
      brandingGet: async () => ({ configured: false }),
      brandingSet: async () => ({ success: true }),
      brandingClear: async () => ({ success: true }),
    };

    // Each method should return something thenable.
    const importResult = api.importKey({ filePath: "/tmp/key.jwk" });
    expect(importResult).toBeInstanceOf(Promise);

    const listResult = api.listKeys();
    expect(listResult).toBeInstanceOf(Promise);

    const generateResult = api.generateKey({});
    expect(generateResult).toBeInstanceOf(Promise);

    const schemaListResult = api.listSchemas();
    expect(schemaListResult).toBeInstanceOf(Promise);

    const schemaGetResult = api.getSchema({ schemaId: "test" });
    expect(schemaGetResult).toBeInstanceOf(Promise);

    const signResult = api.signCredential({ unsignedCredential: "{}", keyId: "k" });
    expect(signResult).toBeInstanceOf(Promise);

    const buildSignResult = api.buildAndSign({
      schemaId: "test",
      issuerDid: "did:test:123",
      credentialSubject: {},
      validFrom: "2025-01-01T00:00:00Z",
      keyId: "k",
    });
    expect(buildSignResult).toBeInstanceOf(Promise);

    const verifyResult = api.verifyCredential({ credential: "{}" });
    expect(verifyResult).toBeInstanceOf(Promise);

    const packageResult = api.packageCredential({ credential: "{}", formats: ["json-ld"] });
    expect(packageResult).toBeInstanceOf(Promise);

    const revQueueResult = api.queueRevocation({
      credentialId: "urn:uuid:test",
      registryUrl: "https://example.com",
    });
    expect(revQueueResult).toBeInstanceOf(Promise);

    const revStatusResult = api.getRevocationStatus();
    expect(revStatusResult).toBeInstanceOf(Promise);

    const revPublishResult = api.publishRevocations({
      dediCredentials: { type: "api-key", apiKey: "test" },
      dediBaseUrl: "https://dedi.example",
    });
    expect(revPublishResult).toBeInstanceOf(Promise);

    const batchStartResult = api.batchStart({
      csvContent: "",
      schemaId: "test",
      issuerDid: "did:test:123",
      validFrom: "2025-01-01T00:00:00Z",
      keyId: "k",
    });
    expect(batchStartResult).toBeInstanceOf(Promise);

    const batchStatusResult = api.batchStatus();
    expect(batchStatusResult).toBeInstanceOf(Promise);

    const batchCancelResult = api.batchCancel();
    expect(batchCancelResult).toBeInstanceOf(Promise);

    const batchExportResult = api.batchExport({ outputPath: "/tmp/batch.zip" });
    expect(batchExportResult).toBeInstanceOf(Promise);

    const openResult = api.openFile({});
    expect(openResult).toBeInstanceOf(Promise);

    const saveResult = api.saveFile({ defaultName: "a.json", content: "{}" });
    expect(saveResult).toBeInstanceOf(Promise);

    const offlineResult = api.getOfflineStatus();
    expect(offlineResult).toBeInstanceOf(Promise);

    const updateCheckResult = api.updateCheck();
    expect(updateCheckResult).toBeInstanceOf(Promise);

    const updateDownloadResult = api.updateDownload();
    expect(updateDownloadResult).toBeInstanceOf(Promise);

    const updateInstallResult = api.updateInstall();
    expect(updateInstallResult).toBeInstanceOf(Promise);

    const updateStatusResult = api.updateGetStatus();
    expect(updateStatusResult).toBeInstanceOf(Promise);

    const getResult = api.getConfig("theme");
    expect(getResult).toBeInstanceOf(Promise);

    const setResult = api.setConfig("theme", "dark");
    expect(setResult).toBeInstanceOf(Promise);

    // Await all to prevent unhandled promise warnings.
    await Promise.all([
      importResult,
      listResult,
      generateResult,
      schemaListResult,
      schemaGetResult,
      signResult,
      buildSignResult,
      verifyResult,
      packageResult,
      revQueueResult,
      revStatusResult,
      revPublishResult,
      batchStartResult,
      batchStatusResult,
      batchCancelResult,
      batchExportResult,
      openResult,
      saveResult,
      offlineResult,
      updateCheckResult,
      updateDownloadResult,
      updateInstallResult,
      updateStatusResult,
      getResult,
      setResult,
    ]);
  });
});
