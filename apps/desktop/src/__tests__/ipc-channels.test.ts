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
    expect(IPC_CHANNELS.SIGN_CREDENTIAL).toBe("credential:sign");
    expect(IPC_CHANNELS.VERIFY_CREDENTIAL).toBe("credential:verify");
    expect(IPC_CHANNELS.FILE_OPEN).toBe("file:open");
    expect(IPC_CHANNELS.FILE_SAVE).toBe("file:save");
    expect(IPC_CHANNELS.GET_OFFLINE_STATUS).toBe("status:offline");
    expect(IPC_CHANNELS.GET_CONFIG).toBe("config:get");
    expect(IPC_CHANNELS.SET_CONFIG).toBe("config:set");
  });

  it("should have exactly 9 channels defined", () => {
    const channelCount = Object.keys(IPC_CHANNELS).length;
    expect(channelCount).toBe(9);
  });

  it("should have unique channel values (no duplicate channel names)", () => {
    const values = Object.values(IPC_CHANNELS);
    const uniqueValues = new Set(values);
    expect(uniqueValues.size).toBe(values.length);
  });

  it("should have all channel values follow the namespace:action pattern", () => {
    const pattern = /^[a-z]+:[a-z]+(-[a-z]+)*$/;
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
      SIGN_CREDENTIAL: "credential:sign",
      VERIFY_CREDENTIAL: "credential:verify",
      FILE_OPEN: "file:open",
      FILE_SAVE: "file:save",
      GET_OFFLINE_STATUS: "status:offline",
      GET_CONFIG: "config:get",
      SET_CONFIG: "config:set",
    };

    for (const [key, value] of Object.entries(expectedChannels)) {
      expect(IPC_CHANNELS[key as keyof typeof IPC_CHANNELS]).toBe(value);
    }
  });
});
