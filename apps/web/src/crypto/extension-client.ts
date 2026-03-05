/**
 * Extension client for communicating with the OpenCred browser extension.
 *
 * Uses window.postMessage to relay requests to the extension's content script,
 * which forwards them to the background service worker, which relays to the
 * native signing host.
 *
 * SECURITY: PIN material travels via postMessage -> content script -> extension
 * -> native host. Used for single C_Login call, immediately discarded. Never
 * stored or logged.
 */

import type {
  CertInfo,
  ExtensionDetectResult,
  SignerMetadata,
  SlotInfo,
  TokenKeyInfo,
} from "./types";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

export class ExtensionNotFoundError extends Error {
  constructor(message = "OpenCred browser extension not found") {
    super(message);
    this.name = "ExtensionNotFoundError";
  }
}

export class NativeHostError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NativeHostError";
  }
}

export class TimeoutError extends Error {
  constructor(message = "Extension request timed out") {
    super(message);
    this.name = "TimeoutError";
  }
}

// ---------------------------------------------------------------------------
// Message protocol
// ---------------------------------------------------------------------------

const REQUEST_TYPE = "opencred-signing-request";
const RESPONSE_TYPE = "opencred-signing-response";
const DETECT_TYPE = "opencred-signing-detect";
const DETECT_RESPONSE_TYPE = "opencred-signing-detect-response";

interface ExtensionRequest {
  type: typeof REQUEST_TYPE;
  id: string;
  operation: string;
  payload: Record<string, unknown>;
}

interface ExtensionResponse {
  type: typeof RESPONSE_TYPE;
  id: string;
  success: boolean;
  result?: Record<string, unknown>;
  error?: { code: string; message: string };
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DETECT_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// Core message sender
// ---------------------------------------------------------------------------

function sendRequest<T>(
  operation: string,
  payload: Record<string, unknown>,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const id = crypto.randomUUID();

    const timer = setTimeout(() => {
      window.removeEventListener("message", handler);
      reject(new TimeoutError());
    }, timeoutMs);

    function handler(event: MessageEvent) {
      if (event.source !== window) return;
      const msg = event.data as Partial<ExtensionResponse>;
      if (msg.type !== RESPONSE_TYPE || msg.id !== id) return;

      clearTimeout(timer);
      window.removeEventListener("message", handler);

      if (msg.success) {
        resolve(msg.result as T);
      } else {
        reject(new NativeHostError(msg.error?.message ?? "Unknown extension error"));
      }
    }

    window.addEventListener("message", handler);

    const request: ExtensionRequest = {
      type: REQUEST_TYPE,
      id,
      operation,
      payload,
    };
    window.postMessage(request, "*");
  });
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

export function detectExtension(
  timeoutMs = DETECT_TIMEOUT_MS,
): Promise<ExtensionDetectResult> {
  return new Promise<ExtensionDetectResult>((resolve) => {
    const timer = setTimeout(() => {
      window.removeEventListener("message", handler);
      resolve({ available: false });
    }, timeoutMs);

    function handler(event: MessageEvent) {
      if (event.source !== window) return;
      const msg = event.data;
      if (!msg || msg.type !== DETECT_RESPONSE_TYPE) return;

      clearTimeout(timer);
      window.removeEventListener("message", handler);
      resolve({ available: true, version: msg.version });
    }

    window.addEventListener("message", handler);
    window.postMessage({ type: DETECT_TYPE }, "*");
  });
}

// ---------------------------------------------------------------------------
// PKCS#11 operations
// ---------------------------------------------------------------------------

export const pkcs11 = {
  listSlots(libraryPath: string): Promise<{ slots: SlotInfo[] }> {
    return sendRequest("pkcs11.listSlots", { libraryPath });
  },

  listKeys(
    libraryPath: string,
    slotIndex: number,
    pin: string,
  ): Promise<{ keys: TokenKeyInfo[] }> {
    return sendRequest("pkcs11.listKeys", { libraryPath, slotIndex, pin });
  },

  connect(opts: {
    libraryPath: string;
    slotIndex: number;
    pin: string;
    keyId?: string;
    label?: string;
  }): Promise<{ signerId: string; metadata: SignerMetadata }> {
    return sendRequest("pkcs11.connect", { ...opts });
  },

  sign(
    signerId: string,
    dataBase64: string,
  ): Promise<{ signature: string }> {
    return sendRequest("pkcs11.sign", { signerId, data: dataBase64 });
  },

  disconnect(signerId: string): Promise<void> {
    return sendRequest("pkcs11.disconnect", { signerId });
  },
};

// ---------------------------------------------------------------------------
// OS Certificate operations
// ---------------------------------------------------------------------------

export const oscert = {
  list(): Promise<{ certificates: CertInfo[] }> {
    return sendRequest("oscert.list", {});
  },

  connect(
    certId: string,
    label?: string,
  ): Promise<{ signerId: string; metadata: SignerMetadata }> {
    return sendRequest("oscert.connect", { certId, label });
  },

  sign(
    signerId: string,
    dataBase64: string,
  ): Promise<{ signature: string }> {
    return sendRequest("oscert.sign", { signerId, data: dataBase64 });
  },

  disconnect(signerId: string): Promise<void> {
    return sendRequest("oscert.disconnect", { signerId });
  },
};
