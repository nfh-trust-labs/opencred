import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  detectExtension,
  pkcs11,
  oscert,
  ExtensionNotFoundError,
  NativeHostError,
  TimeoutError,
} from "../extension-client";

/**
 * Mock postMessage to intercept outgoing requests and dispatch responses
 * synchronously via MessageEvent. happy-dom's postMessage doesn't reliably
 * trigger message events, so we bypass it entirely.
 */

type ResponseRule = {
  result: unknown;
  success: boolean;
  error?: { code: string; message: string };
};

let nextResponse: ResponseRule | null = null;
let nextDetectResponse: boolean = false;
let capturedRequests: Array<{ operation: string; payload: Record<string, unknown>; id: string }> = [];
let originalPostMessage: typeof window.postMessage;

function setupMockPostMessage() {
  originalPostMessage = window.postMessage.bind(window);

  window.postMessage = vi.fn((message: unknown) => {
    const msg = message as { type?: string; id?: string; operation?: string; payload?: Record<string, unknown> };

    // Handle detect messages
    if (msg?.type === "opencred-signing-detect") {
      if (nextDetectResponse) {
        nextDetectResponse = false;
        const event = new MessageEvent("message", {
          data: { type: "opencred-signing-detect-response", available: true, version: "1.0.0" },
          source: window,
        });
        window.dispatchEvent(event);
      }
      return;
    }

    if (msg?.type !== "opencred-signing-request") return;

    capturedRequests.push({
      operation: msg.operation!,
      payload: msg.payload!,
      id: msg.id!,
    });

    if (nextResponse) {
      const rule = nextResponse;
      nextResponse = null;
      const response = {
        type: "opencred-signing-response",
        id: msg.id,
        success: rule.success,
        ...(rule.success ? { result: rule.result } : { error: rule.error }),
      };
      const event = new MessageEvent("message", {
        data: response,
        source: window,
      });
      window.dispatchEvent(event);
    }
  }) as unknown as typeof window.postMessage;
}

function queueResponse(result: unknown, opts: { success?: boolean; error?: string } = {}) {
  const success = opts.success ?? true;
  nextResponse = {
    result,
    success,
    error: success ? undefined : { code: "ERROR", message: opts.error ?? "Unknown error" },
  };
}

function queueDetectResponse() {
  nextDetectResponse = true;
}

describe("extension-client", () => {
  beforeEach(() => {
    capturedRequests = [];
    nextResponse = null;
    setupMockPostMessage();
  });

  afterEach(() => {
    window.postMessage = originalPostMessage;
  });

  describe("detectExtension", () => {
    it("returns { available: true } when extension responds", async () => {
      queueDetectResponse();
      const result = await detectExtension();
      expect(result).toEqual({ available: true, version: "1.0.0" });
    });

    it("returns { available: false } on timeout", async () => {
      vi.useFakeTimers();
      // Don't queue a response — let it time out
      const promise = detectExtension(50);
      vi.advanceTimersByTime(100);
      const result = await promise;
      expect(result).toEqual({ available: false });
      vi.useRealTimers();
    });
  });

  describe("pkcs11.connect", () => {
    it("sends correct message and returns response", async () => {
      const responseData = {
        signerId: "signer-123",
        metadata: {
          id: "did:key:z...",
          algorithm: "P-256",
          type: "pkcs11",
          fingerprint: "abc123",
          label: "My Token",
        },
      };
      queueResponse(responseData);

      const result = await pkcs11.connect({
        libraryPath: "/usr/lib/opensc-pkcs11.so",
        slotIndex: 0,
        pin: "1234",
        keyId: "key-1",
      });

      expect(capturedRequests).toHaveLength(1);
      expect(capturedRequests[0].operation).toBe("pkcs11.connect");
      expect(capturedRequests[0].payload).toEqual({
        libraryPath: "/usr/lib/opensc-pkcs11.so",
        slotIndex: 0,
        pin: "1234",
        keyId: "key-1",
      });
      expect(result.signerId).toBe("signer-123");
      expect(result.metadata.type).toBe("pkcs11");
    });
  });

  describe("pkcs11.sign", () => {
    it("sends correct message and returns signature", async () => {
      queueResponse({ signature: "AQID" });

      const result = await pkcs11.sign("signer-123", "AQID");

      expect(capturedRequests).toHaveLength(1);
      expect(capturedRequests[0].operation).toBe("pkcs11.sign");
      expect(capturedRequests[0].payload).toEqual({
        signerId: "signer-123",
        dataBase64: "AQID",
      });
      expect(result.signature).toBe("AQID");
    });
  });

  describe("oscert.list", () => {
    it("returns certificate array", async () => {
      const certs = [
        {
          id: "cert-1",
          subject: "CN=Test",
          issuer: "CN=CA",
          serialNumber: "01",
          validFrom: "2025-01-01",
          validUntil: "2026-01-01",
          keyAlgorithm: "EC",
          isExportable: false,
          thumbprint: "aabbcc",
        },
      ];
      queueResponse({ certificates: certs });

      const result = await oscert.list();
      expect(result.certificates).toHaveLength(1);
      expect(result.certificates[0].subject).toBe("CN=Test");
    });
  });

  describe("error handling", () => {
    it("timeout throws TimeoutError", async () => {
      vi.useFakeTimers();
      // Don't queue a response — let it time out
      const promise = pkcs11.sign("signer-123", "AQID");
      vi.advanceTimersByTime(35_000);
      await expect(promise).rejects.toThrow(TimeoutError);
      vi.useRealTimers();
    });

    it("error response throws NativeHostError", async () => {
      queueResponse(null, { success: false, error: "Token removed" });

      await expect(pkcs11.sign("signer-123", "AQID")).rejects.toThrow(
        NativeHostError,
      );
    });

    it("error response includes message", async () => {
      queueResponse(null, { success: false, error: "Token removed" });

      await expect(pkcs11.sign("signer-123", "AQID")).rejects.toThrow(
        "Token removed",
      );
    });
  });

  describe("request ID uniqueness", () => {
    it("request IDs are unique across calls", async () => {
      queueResponse({ slots: [] });
      await pkcs11.listSlots("lib-a");

      queueResponse({ slots: [] });
      await pkcs11.listSlots("lib-b");

      expect(capturedRequests).toHaveLength(2);
      expect(capturedRequests[0].id).not.toBe(capturedRequests[1].id);
    });
  });
});

describe("error classes", () => {
  it("ExtensionNotFoundError", () => {
    const err = new ExtensionNotFoundError();
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("ExtensionNotFoundError");
    expect(err.message).toBe("OpenCred browser extension not found");
  });

  it("NativeHostError", () => {
    const err = new NativeHostError("token removed");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("NativeHostError");
    expect(err.message).toBe("token removed");
  });

  it("TimeoutError", () => {
    const err = new TimeoutError();
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("TimeoutError");
    expect(err.message).toBe("Extension request timed out");
  });
});
