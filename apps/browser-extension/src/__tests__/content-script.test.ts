/**
 * Tests for the content script.
 *
 * @vitest-environment jsdom
 *
 * Validates:
 *  - Extension detection via postMessage
 *  - Signing request relay from page to background
 *  - Error handling when background is unreachable
 *  - Ignores messages from other sources
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  PAGE_REQUEST_TYPE,
  PAGE_RESPONSE_TYPE,
  PAGE_DETECT_TYPE,
  PAGE_DETECT_RESPONSE_TYPE,
  EXTENSION_VERSION,
} from "../types.js";

// chrome global is set up by chrome-mock-setup.ts (vitest setupFiles)
const mockChrome = (globalThis as Record<string, unknown>)["chrome"] as Record<string, Record<string, unknown>>;
const mockSendMessage = (mockChrome["runtime"] as Record<string, unknown>)["sendMessage"] as ReturnType<typeof vi.fn>;

describe("content-script types", () => {
  it("should define correct message type constants", () => {
    expect(PAGE_REQUEST_TYPE).toBe("opencred-signing-request");
    expect(PAGE_RESPONSE_TYPE).toBe("opencred-signing-response");
    expect(PAGE_DETECT_TYPE).toBe("opencred-signing-detect");
    expect(PAGE_DETECT_RESPONSE_TYPE).toBe("opencred-signing-detect-response");
  });

  it("should define extension version", () => {
    expect(EXTENSION_VERSION).toBe("0.1.0");
  });
});

describe("content-script message handling", () => {
  let messageHandler: ((event: Event) => void) | undefined;
  let postMessageSpy: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    vi.clearAllMocks();
    messageHandler = undefined;
    (mockChrome["runtime"] as Record<string, unknown>)["lastError"] = null;

    // Capture addEventListener calls
    const addSpy = vi.spyOn(window, "addEventListener");
    postMessageSpy = vi.fn();
    vi.spyOn(window, "postMessage").mockImplementation(postMessageSpy);

    // Re-import content script to trigger listener registration
    vi.resetModules();
    await import("../content-script.js");

    for (const call of addSpy.mock.calls) {
      if (call[0] === "message") {
        messageHandler = call[1] as (event: Event) => void;
      }
    }
  });

  function makeEvent(data: unknown, source?: unknown): MessageEvent {
    const event = new MessageEvent("message", { data });
    Object.defineProperty(event, "source", { value: source ?? window });
    return event;
  }

  it("should register a message event listener", () => {
    expect(messageHandler).toBeDefined();
  });

  it("should respond to detect requests", () => {
    messageHandler!(makeEvent({ type: PAGE_DETECT_TYPE }));

    expect(postMessageSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: PAGE_DETECT_RESPONSE_TYPE,
        available: true,
        version: EXTENSION_VERSION,
      }),
      "*",
    );
  });

  it("should relay signing requests to background", () => {
    messageHandler!(makeEvent({
      type: PAGE_REQUEST_TYPE,
      id: "req-123",
      operation: "pkcs11_detect",
      payload: {},
    }));

    expect(mockSendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "signing-request",
        id: "req-123",
        operation: "pkcs11_detect",
      }),
      expect.any(Function),
    );
  });

  it("should relay background response back to page", () => {
    messageHandler!(makeEvent({
      type: PAGE_REQUEST_TYPE,
      id: "req-456",
      operation: "pkcs11_detect",
      payload: {},
    }));

    // Extract and call the sendMessage callback
    const callback = mockSendMessage.mock.calls[0][1] as (response: unknown) => void;
    callback({
      id: "req-456",
      success: true,
      result: { available: true },
    });

    expect(postMessageSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: PAGE_RESPONSE_TYPE,
        id: "req-456",
        success: true,
      }),
      "*",
    );
  });

  it("should send error when background communication fails", () => {
    (mockChrome["runtime"] as Record<string, unknown>)["lastError"] = { message: "Error" };

    messageHandler!(makeEvent({
      type: PAGE_REQUEST_TYPE,
      id: "req-789",
      operation: "pkcs11_detect",
      payload: {},
    }));

    const callback = mockSendMessage.mock.calls[0][1] as (response: unknown) => void;
    callback(undefined);

    expect(postMessageSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: PAGE_RESPONSE_TYPE,
        id: "req-789",
        success: false,
        error: expect.objectContaining({ code: "EXTENSION_ERROR" }),
      }),
      "*",
    );
  });

  it("should ignore messages from other sources", () => {
    messageHandler!(makeEvent(
      { type: PAGE_REQUEST_TYPE, id: "x", operation: "test", payload: {} },
      {}, // not window
    ));

    expect(mockSendMessage).not.toHaveBeenCalled();
  });

  it("should ignore non-object messages", () => {
    messageHandler!(makeEvent("string"));
    messageHandler!(makeEvent(null));

    expect(mockSendMessage).not.toHaveBeenCalled();
  });
});
