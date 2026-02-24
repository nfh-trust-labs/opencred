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
  [IPC_CHANNELS.SIGN_CREDENTIAL]: "signCredential",
  [IPC_CHANNELS.VERIFY_CREDENTIAL]: "verifyCredential",
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
      signCredential: async () => ({ success: false, error: "stub" }),
      verifyCredential: async () => ({ success: true, valid: true }),
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
      signCredential: async () => ({ success: false, error: "stub" }),
      verifyCredential: async () => ({ success: true, valid: true }),
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

    const signResult = api.signCredential({ unsignedCredential: "{}", keyId: "k" });
    expect(signResult).toBeInstanceOf(Promise);

    const verifyResult = api.verifyCredential({ credential: "{}" });
    expect(verifyResult).toBeInstanceOf(Promise);

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
      signResult,
      verifyResult,
      openResult,
      saveResult,
      offlineResult,
      getResult,
      setResult,
    ]);
  });
});
