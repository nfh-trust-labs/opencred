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
 * Mapping from IPC channel constants to the expected method names on
 * OpenCredDesktopAPI. This is the source of truth for ensuring complete
 * coverage between channels and API methods.
 */
const CHANNEL_TO_METHOD: Record<string, keyof OpenCredDesktopAPI> = {
  [IPC_CHANNELS.KEY_IMPORT]: "importKey",
  [IPC_CHANNELS.KEY_LIST]: "listKeys",
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
  [IPC_CHANNELS.GET_CONFIG]: "getConfig",
  [IPC_CHANNELS.SET_CONFIG]: "setConfig",
};

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

  it("should have unique method names (no two channels map to the same method)", () => {
    const methods = Object.values(CHANNEL_TO_METHOD);
    const uniqueMethods = new Set(methods);
    expect(uniqueMethods.size).toBe(methods.length);
  });

  it("should have all mapped methods present on a conforming API object", () => {
    // Create a minimal mock that satisfies OpenCredDesktopAPI.
    const api: OpenCredDesktopAPI = {
      importKey: async () => ({ success: true }),
      listKeys: async () => ({ keys: [] }),
      listSchemas: async () => ({ schemas: [] }),
      getSchema: async () => ({ id: "test", schema: {} }),
      signCredential: async () => ({ success: false, error: "stub" }),
      buildAndSign: async () => ({ success: false, error: "stub" }),
      verifyCredential: async () => ({ success: true, valid: true }),
      packageCredential: async () => ({ success: true }),
      queueRevocation: async () => ({ success: true }),
      getRevocationStatus: async () => ({ items: [] }),
      publishRevocations: async () => ({ results: [] }),
      batchStart: async () => ({ success: true }),
      batchStatus: async () => ({ total: 0, completed: 0, successCount: 0, errorCount: 0, skippedCount: 0, running: false, cancelled: false, rows: [] }),
      batchCancel: async () => ({ success: true }),
      batchExport: async () => ({ success: true }),
      openFile: async () => ({ content: null, filePath: null }),
      saveFile: async () => ({ filePath: null }),
      getOfflineStatus: async () => false,
      getConfig: async () => undefined,
      setConfig: async () => {},
    };

    for (const methodName of Object.values(CHANNEL_TO_METHOD)) {
      expect(typeof api[methodName]).toBe("function");
    }
  });

  it("should have all API methods return promises", async () => {
    const api: OpenCredDesktopAPI = {
      importKey: async () => ({ success: true }),
      listKeys: async () => ({ keys: [] }),
      listSchemas: async () => ({ schemas: [] }),
      getSchema: async () => ({ id: "test", schema: {} }),
      signCredential: async () => ({ success: false, error: "stub" }),
      buildAndSign: async () => ({ success: false, error: "stub" }),
      verifyCredential: async () => ({ success: true, valid: true }),
      packageCredential: async () => ({ success: true }),
      queueRevocation: async () => ({ success: true }),
      getRevocationStatus: async () => ({ items: [] }),
      publishRevocations: async () => ({ results: [] }),
      batchStart: async () => ({ success: true }),
      batchStatus: async () => ({ total: 0, completed: 0, successCount: 0, errorCount: 0, skippedCount: 0, running: false, cancelled: false, rows: [] }),
      batchCancel: async () => ({ success: true }),
      batchExport: async () => ({ success: true }),
      openFile: async () => ({ content: null, filePath: null }),
      saveFile: async () => ({ filePath: null }),
      getOfflineStatus: async () => false,
      getConfig: async () => undefined,
      setConfig: async () => {},
    };

    // Each method should return something thenable.
    const importResult = api.importKey({ filePath: "/tmp/key.jwk" });
    expect(importResult).toBeInstanceOf(Promise);

    const listResult = api.listKeys();
    expect(listResult).toBeInstanceOf(Promise);

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

    const revPublishResult = api.publishRevocations();
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

    const getResult = api.getConfig("theme");
    expect(getResult).toBeInstanceOf(Promise);

    const setResult = api.setConfig("theme", "dark");
    expect(setResult).toBeInstanceOf(Promise);

    // Await all to prevent unhandled promise warnings.
    await Promise.all([
      importResult,
      listResult,
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
      getResult,
      setResult,
    ]);
  });
});
