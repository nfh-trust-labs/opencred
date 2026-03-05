/**
 * Background service worker for the OpenCred signing extension.
 *
 * Receives messages from content scripts, validates origins, and relays
 * requests to the native messaging host via connectNative.
 *
 * SECURITY (3-layer origin validation):
 *  1. Extension manifest "matches" restricts content script injection
 *  2. This background script checks origin against a hardcoded allowlist
 *  3. The native host independently validates origin
 *
 * Native host connection lifecycle:
 *  - Connect on first request (lazy)
 *  - Keep connection alive for subsequent requests
 *  - Reconnect on disconnect or error
 *  - Pending requests get error responses on unexpected disconnect
 */

import {
  NATIVE_HOST_NAME,
  type RuntimeRequest,
  type RuntimeResponse,
} from "./types.js";

// ---------------------------------------------------------------------------
// Origin allowlist (layer 2 of 3)
// ---------------------------------------------------------------------------

/**
 * Hardcoded allowlist of web origins permitted to use the signing API.
 * These should be the OpenCred web app origins.
 *
 * SECURITY: This is a defense-in-depth check. The content script is only
 * injected into matching pages (manifest matches), and the native host
 * does its own validation. But we check here too.
 */
const ALLOWED_ORIGINS = new Set<string>([
  "https://web-production-34243.up.railway.app",
]);

/**
 * Additional origins loaded from extension storage (for development).
 * Populated at startup from chrome.storage.local.
 */
const dynamicOrigins = new Set<string>();

function isOriginAllowed(origin: string): boolean {
  if (!origin || typeof origin !== "string") return false;
  return ALLOWED_ORIGINS.has(origin) || dynamicOrigins.has(origin);
}

// Load dynamic origins from storage at startup
chrome.storage?.local?.get(["allowedOrigins"], (result) => {
  if (Array.isArray(result?.["allowedOrigins"])) {
    for (const origin of result["allowedOrigins"]) {
      if (typeof origin === "string") dynamicOrigins.add(origin);
    }
  }
});

// ---------------------------------------------------------------------------
// Native host connection management
// ---------------------------------------------------------------------------

const REQUEST_TIMEOUT_MS = 30_000;

let nativePort: chrome.runtime.Port | null = null;
const pendingRequests = new Map<string, { callback: (response: RuntimeResponse) => void; timer: ReturnType<typeof setTimeout> }>();

function clearPendingRequests(): void {
  for (const [, entry] of pendingRequests) {
    clearTimeout(entry.timer);
  }
  pendingRequests.clear();
}

function ensureNativeConnection(): chrome.runtime.Port {
  if (nativePort) return nativePort;

  nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);

  nativePort.onMessage.addListener((message: Record<string, unknown>) => {
    const id = message["id"] as string | undefined;
    if (!id) return;

    const entry = pendingRequests.get(id);
    if (entry) {
      clearTimeout(entry.timer);
      pendingRequests.delete(id);
      entry.callback({
        id,
        success: message["success"] as boolean,
        result: message["result"] as Record<string, unknown> | undefined,
        error: message["error"] as { code: string; message: string } | undefined,
      });
    }
  });

  nativePort.onDisconnect.addListener(() => {
    nativePort = null;

    // Reject all pending requests
    for (const [id, entry] of pendingRequests) {
      clearTimeout(entry.timer);
      entry.callback({
        id,
        success: false,
        error: {
          code: "NATIVE_HOST_DISCONNECTED",
          message: "Native host disconnected unexpectedly",
        },
      });
    }
    pendingRequests.clear();
  });

  return nativePort;
}

// ---------------------------------------------------------------------------
// Operation name mapping
// ---------------------------------------------------------------------------

/**
 * Map web UI operation names (dot notation from extension-client.ts) to
 * native host operation types (underscore notation from protocol.ts).
 *
 * Web UI sends:   "pkcs11.listSlots"
 * Native expects: "pkcs11_list_slots"
 */
const OPERATION_MAP: Record<string, string> = {
  "pkcs11.listSlots": "pkcs11_list_slots",
  "pkcs11.listKeys": "pkcs11_list_keys",
  "pkcs11.connect": "pkcs11_connect",
  "pkcs11.sign": "pkcs11_sign",
  "pkcs11.disconnect": "pkcs11_disconnect",
  "oscert.list": "oscert_list",
  "oscert.connect": "oscert_connect",
  "oscert.sign": "oscert_sign",
  "oscert.disconnect": "oscert_disconnect",
};

// ---------------------------------------------------------------------------
// Message handling
// ---------------------------------------------------------------------------

function handleRuntimeMessage(
  message: RuntimeRequest,
  _sender: chrome.runtime.MessageSender,
  sendResponse: (response: RuntimeResponse) => void,
): boolean {
  if (message.action !== "signing-request") return false;

  // Layer 2 origin validation
  if (!isOriginAllowed(message.origin)) {
    sendResponse({
      id: message.id,
      success: false,
      error: {
        code: "ORIGIN_REJECTED",
        message: "Origin not in extension allowlist",
      },
    });
    return false; // Synchronous response
  }

  // Map operation name from web UI format to native host format
  const nativeOperation = OPERATION_MAP[message.operation] ?? message.operation;

  // Relay to native host
  try {
    const port = ensureNativeConnection();

    const timer = setTimeout(() => {
      pendingRequests.delete(message.id);
      sendResponse({
        id: message.id,
        success: false,
        error: { code: "TIMEOUT", message: "Native host did not respond in time" },
      });
    }, REQUEST_TIMEOUT_MS);

    pendingRequests.set(message.id, { callback: sendResponse, timer });

    port.postMessage({
      id: message.id,
      type: nativeOperation,
      origin: message.origin,
      payload: message.payload,
    });
  } catch {
    sendResponse({
      id: message.id,
      success: false,
      error: {
        code: "NATIVE_HOST_ERROR",
        message: "Failed to connect to native signing host",
      },
    });
    return false;
  }

  // Return true to indicate we'll send the response asynchronously
  return true;
}

// Register the message listener
chrome.runtime.onMessage.addListener(handleRuntimeMessage);

// Export for testing
export { handleRuntimeMessage, isOriginAllowed, ALLOWED_ORIGINS, clearPendingRequests, OPERATION_MAP };
