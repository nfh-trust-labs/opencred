/**
 * Tests for the background service worker.
 *
 * Validates:
 *  - Origin validation (allowlist checks)
 *  - Native host message relay
 *  - Pending request management
 *  - Disconnect error handling
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { NATIVE_HOST_NAME, type RuntimeRequest } from "../types.js";
import { chromeMock, mockPort, TEST_ORIGIN } from "./chrome-mock-setup.js";

// ---------------------------------------------------------------------------
// Import background — module top-level code runs and registers listeners.
// The chrome global + storage is already set by setupFiles.
// ---------------------------------------------------------------------------

import {
  handleRuntimeMessage,
  isOriginAllowed,
  clearPendingRequests,
  OPERATION_MAP,
} from "../background.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type MessageCallback = (message: Record<string, unknown>) => void;
type DisconnectCallback = () => void;

let nativePortMessageCb: MessageCallback | undefined;
let nativePortDisconnectCb: DisconnectCallback | undefined;

function makeRequest(id: string, operation = "pkcs11.sign"): RuntimeRequest {
  return {
    action: "signing-request",
    id,
    operation,
    origin: TEST_ORIGIN,
    payload: {},
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("background types", () => {
  it("should use the correct native host name", () => {
    expect(NATIVE_HOST_NAME).toBe("com.opencred.signing");
  });
});

describe("operation name mapping", () => {
  it("should map all 9 web UI operations to native host format", () => {
    expect(Object.keys(OPERATION_MAP)).toHaveLength(9);
  });

  it("should convert dot notation to underscore notation", () => {
    expect(OPERATION_MAP["pkcs11.listSlots"]).toBe("pkcs11_list_slots");
    expect(OPERATION_MAP["pkcs11.listKeys"]).toBe("pkcs11_list_keys");
    expect(OPERATION_MAP["pkcs11.connect"]).toBe("pkcs11_connect");
    expect(OPERATION_MAP["pkcs11.sign"]).toBe("pkcs11_sign");
    expect(OPERATION_MAP["pkcs11.disconnect"]).toBe("pkcs11_disconnect");
    expect(OPERATION_MAP["oscert.list"]).toBe("oscert_list");
    expect(OPERATION_MAP["oscert.connect"]).toBe("oscert_connect");
    expect(OPERATION_MAP["oscert.sign"]).toBe("oscert_sign");
    expect(OPERATION_MAP["oscert.disconnect"]).toBe("oscert_disconnect");
  });
});

describe("message handler registration", () => {
  it("should register a runtime message listener", () => {
    expect(chromeMock.runtime.onMessage.addListener).toHaveBeenCalled();
  });
});

describe("origin validation", () => {
  it("should reject unknown origins", () => {
    expect(isOriginAllowed("https://evil.example.com")).toBe(false);
  });

  it("should reject empty origins", () => {
    expect(isOriginAllowed("")).toBe(false);
  });

  it("should accept the test origin (from dynamic storage)", () => {
    expect(isOriginAllowed(TEST_ORIGIN)).toBe(true);
  });
});

describe("origin rejection via handler", () => {
  it("should reject requests with disallowed origins", () => {
    const sendResponse = vi.fn();
    const request: RuntimeRequest = {
      action: "signing-request",
      id: "req-rej-1",
      operation: "pkcs11_detect",
      origin: "https://evil.example.com",
      payload: {},
    };

    const result = handleRuntimeMessage(request, {} as chrome.runtime.MessageSender, sendResponse);

    expect(result).toBe(false);
    expect(sendResponse).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        error: expect.objectContaining({ code: "ORIGIN_REJECTED" }),
      }),
    );
  });

  it("should ignore non-signing-request messages", () => {
    const sendResponse = vi.fn();
    const result = handleRuntimeMessage(
      { action: "other" } as unknown as RuntimeRequest,
      {} as chrome.runtime.MessageSender,
      sendResponse,
    );

    expect(result).toBe(false);
    expect(sendResponse).not.toHaveBeenCalled();
  });
});

describe("native host relay", () => {
  beforeEach(() => {
    // Step 1: Force-disconnect the background module's cached nativePort
    // by calling the disconnect callback registered in the PREVIOUS test.
    // We extract it from the mock's recorded calls since our local variable
    // is about to be reset.
    const disconnectCalls = mockPort.onDisconnect.addListener.mock.calls;
    if (disconnectCalls.length > 0) {
      const lastCb = disconnectCalls[disconnectCalls.length - 1][0] as DisconnectCallback;
      lastCb();
    }

    // Step 2: Reset everything
    nativePortMessageCb = undefined;
    nativePortDisconnectCb = undefined;
    clearPendingRequests();

    mockPort.postMessage.mockClear();
    chromeMock.runtime.connectNative.mockClear();
    chromeMock.runtime.connectNative.mockReturnValue(mockPort);
    mockPort.onMessage.addListener.mockClear();
    mockPort.onMessage.addListener.mockImplementation((cb: MessageCallback) => {
      nativePortMessageCb = cb;
    });
    mockPort.onDisconnect.addListener.mockClear();
    mockPort.onDisconnect.addListener.mockImplementation((cb: DisconnectCallback) => {
      nativePortDisconnectCb = cb;
    });
  });

  it("should connect to native host and relay request", () => {
    const sendResponse = vi.fn();

    const result = handleRuntimeMessage(makeRequest("req-relay-1"), {} as chrome.runtime.MessageSender, sendResponse);

    expect(result).toBe(true);
    expect(chromeMock.runtime.connectNative).toHaveBeenCalledWith(NATIVE_HOST_NAME);
    expect(mockPort.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "req-relay-1",
        type: "pkcs11_sign",
        origin: TEST_ORIGIN,
      }),
    );
  });

  it("should route native host response back to sender", () => {
    const sendResponse = vi.fn();

    handleRuntimeMessage(makeRequest("req-relay-2"), {} as chrome.runtime.MessageSender, sendResponse);

    expect(nativePortMessageCb).toBeDefined();
    nativePortMessageCb!({
      id: "req-relay-2",
      success: true,
      result: { available: true },
    });

    expect(sendResponse).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "req-relay-2",
        success: true,
        result: { available: true },
      }),
    );
  });

  it("should reject pending requests on native host disconnect", () => {
    const sendResponse1 = vi.fn();
    const sendResponse2 = vi.fn();

    handleRuntimeMessage(makeRequest("req-d1"), {} as chrome.runtime.MessageSender, sendResponse1);
    handleRuntimeMessage(makeRequest("req-d2"), {} as chrome.runtime.MessageSender, sendResponse2);

    expect(nativePortDisconnectCb).toBeDefined();
    nativePortDisconnectCb!();

    expect(sendResponse1).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        error: expect.objectContaining({ code: "NATIVE_HOST_DISCONNECTED" }),
      }),
    );
    expect(sendResponse2).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        error: expect.objectContaining({ code: "NATIVE_HOST_DISCONNECTED" }),
      }),
    );
  });

  it("should reuse native host connection for multiple requests", () => {
    handleRuntimeMessage(makeRequest("req-r1"), {} as chrome.runtime.MessageSender, vi.fn());
    handleRuntimeMessage(makeRequest("req-r2"), {} as chrome.runtime.MessageSender, vi.fn());

    expect(chromeMock.runtime.connectNative).toHaveBeenCalledTimes(1);
  });

  it("should reconnect after disconnect", () => {
    handleRuntimeMessage(makeRequest("req-rc1"), {} as chrome.runtime.MessageSender, vi.fn());

    // Disconnect
    nativePortDisconnectCb!();
    clearPendingRequests();

    // Re-set mocks for new connection
    mockPort.onMessage.addListener.mockImplementation((cb: MessageCallback) => {
      nativePortMessageCb = cb;
    });
    mockPort.onDisconnect.addListener.mockImplementation((cb: DisconnectCallback) => {
      nativePortDisconnectCb = cb;
    });

    handleRuntimeMessage(makeRequest("req-rc2"), {} as chrome.runtime.MessageSender, vi.fn());

    expect(chromeMock.runtime.connectNative).toHaveBeenCalledTimes(2);
  });
});
