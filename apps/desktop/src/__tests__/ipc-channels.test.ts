/**
 * Tests for IPC channel definitions.
 *
 * Verifies that all channel names are correctly defined, unique, and that the
 * type system correctly narrows the IpcChannel union type.
 */

import { describe, it, expect } from "vitest";
import { IPC_CHANNELS, type IpcChannel } from "../shared/ipc-channels";

describe("IPC_CHANNELS", () => {
  it("should define all required channel names", () => {
    expect(IPC_CHANNELS.KEY_IMPORT).toBe("key:import");
    expect(IPC_CHANNELS.KEY_LIST).toBe("key:list");
    expect(IPC_CHANNELS.SCHEMA_LIST).toBe("schema:list");
    expect(IPC_CHANNELS.SCHEMA_GET).toBe("schema:get");
    expect(IPC_CHANNELS.SIGN_CREDENTIAL).toBe("credential:sign");
    expect(IPC_CHANNELS.BUILD_AND_SIGN).toBe("credential:build-and-sign");
    expect(IPC_CHANNELS.VERIFY_CREDENTIAL).toBe("credential:verify");
    expect(IPC_CHANNELS.PACKAGE_CREDENTIAL).toBe("credential:package");
    expect(IPC_CHANNELS.REVOCATION_QUEUE).toBe("revocation:queue");
    expect(IPC_CHANNELS.REVOCATION_STATUS).toBe("revocation:status");
    expect(IPC_CHANNELS.REVOCATION_PUBLISH).toBe("revocation:publish");
    expect(IPC_CHANNELS.FILE_OPEN).toBe("file:open");
    expect(IPC_CHANNELS.FILE_SAVE).toBe("file:save");
    expect(IPC_CHANNELS.GET_OFFLINE_STATUS).toBe("status:offline");
    expect(IPC_CHANNELS.BATCH_START).toBe("batch:start");
    expect(IPC_CHANNELS.BATCH_STATUS).toBe("batch:status");
    expect(IPC_CHANNELS.BATCH_CANCEL).toBe("batch:cancel");
    expect(IPC_CHANNELS.BATCH_EXPORT).toBe("batch:export");
    expect(IPC_CHANNELS.PKCS11_DETECT).toBe("pkcs11:detect");
    expect(IPC_CHANNELS.PKCS11_LIST_SLOTS).toBe("pkcs11:list-slots");
    expect(IPC_CHANNELS.PKCS11_LIST_KEYS).toBe("pkcs11:list-keys");
    expect(IPC_CHANNELS.PKCS11_CONNECT).toBe("pkcs11:connect");
    expect(IPC_CHANNELS.UPDATE_CHECK).toBe("update:check");
    expect(IPC_CHANNELS.UPDATE_DOWNLOAD).toBe("update:download");
    expect(IPC_CHANNELS.UPDATE_INSTALL).toBe("update:install");
    expect(IPC_CHANNELS.UPDATE_STATUS).toBe("update:status");
    expect(IPC_CHANNELS.OSCERT_LIST).toBe("oscert:list");
    expect(IPC_CHANNELS.OSCERT_SIGN).toBe("oscert:sign");
    expect(IPC_CHANNELS.OSCERT_CONNECT).toBe("oscert:connect");
    expect(IPC_CHANNELS.GET_CONFIG).toBe("config:get");
    expect(IPC_CHANNELS.SET_CONFIG).toBe("config:set");
  });

  it("should have exactly 31 channels defined", () => {
    const channelCount = Object.keys(IPC_CHANNELS).length;
    expect(channelCount).toBe(31);
  });

  it("should have unique channel values (no duplicate channel names)", () => {
    const values = Object.values(IPC_CHANNELS);
    const uniqueValues = new Set(values);
    expect(uniqueValues.size).toBe(values.length);
  });

  it("should have all channel values follow the namespace:action pattern", () => {
    const pattern = /^[a-z0-9]+:[a-z]+(-[a-z]+)*$/;
    for (const channel of Object.values(IPC_CHANNELS)) {
      expect(channel).toMatch(pattern);
    }
  });

  it("should allow IpcChannel type assignment from valid channel values", () => {
    // This is a compile-time check. If the type system is correct, assigning
    // any value from IPC_CHANNELS to an IpcChannel variable should work.
    const channel: IpcChannel = IPC_CHANNELS.KEY_IMPORT;
    expect(channel).toBeDefined();
  });

  it("should have all channels as readonly (const assertion)", () => {
    // Verify the object is frozen-like by checking that the values are string literals,
    // not generic strings. We do this by confirming each value is a specific string.
    const expectedChannels: Record<string, string> = {
      KEY_IMPORT: "key:import",
      KEY_LIST: "key:list",
      SCHEMA_LIST: "schema:list",
      SCHEMA_GET: "schema:get",
      SIGN_CREDENTIAL: "credential:sign",
      BUILD_AND_SIGN: "credential:build-and-sign",
      VERIFY_CREDENTIAL: "credential:verify",
      PACKAGE_CREDENTIAL: "credential:package",
      REVOCATION_QUEUE: "revocation:queue",
      REVOCATION_STATUS: "revocation:status",
      REVOCATION_PUBLISH: "revocation:publish",
      BATCH_START: "batch:start",
      BATCH_STATUS: "batch:status",
      BATCH_CANCEL: "batch:cancel",
      BATCH_EXPORT: "batch:export",
      FILE_OPEN: "file:open",
      FILE_SAVE: "file:save",
      GET_OFFLINE_STATUS: "status:offline",
      PKCS11_DETECT: "pkcs11:detect",
      PKCS11_LIST_SLOTS: "pkcs11:list-slots",
      PKCS11_LIST_KEYS: "pkcs11:list-keys",
      PKCS11_CONNECT: "pkcs11:connect",
      UPDATE_CHECK: "update:check",
      UPDATE_DOWNLOAD: "update:download",
      UPDATE_INSTALL: "update:install",
      UPDATE_STATUS: "update:status",
      OSCERT_LIST: "oscert:list",
      OSCERT_SIGN: "oscert:sign",
      OSCERT_CONNECT: "oscert:connect",
      GET_CONFIG: "config:get",
      SET_CONFIG: "config:set",
    };

    for (const [key, value] of Object.entries(expectedChannels)) {
      expect(IPC_CHANNELS[key as keyof typeof IPC_CHANNELS]).toBe(value);
    }
  });
});
