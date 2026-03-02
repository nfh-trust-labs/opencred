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
const ALLOWED_ORIGINS: string[] = [
  // Add production origins here when deployed
  // "https://app.opencred.example.com",
];

/**
 * Additional origins loaded from extension storage (for development).
 * Populated at startup from chrome.storage.local.
 */
let dynamicOrigins: string[] = [];

function isOriginAllowed(origin: string): boolean {
  if (!origin || typeof origin !== "string") return false;
  return ALLOWED_ORIGINS.includes(origin) || dynamicOrigins.includes(origin);
}

// Load dynamic origins from storage at startup
chrome.storage?.local?.get(["allowedOrigins"], (result) => {
  if (Array.isArray(result?.["allowedOrigins"])) {
    dynamicOrigins = result["allowedOrigins"];
  }
});

// ---------------------------------------------------------------------------
// Native host connection management
// ---------------------------------------------------------------------------

let nativePort: chrome.runtime.Port | null = null;
const pendingRequests = new Map<string, (response: RuntimeResponse) => void>();

function ensureNativeConnection(): chrome.runtime.Port {
  if (nativePort) return nativePort;

  nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);

  nativePort.onMessage.addListener((message: Record<string, unknown>) => {
    const id = message["id"] as string | undefined;
    if (!id) return;

    const callback = pendingRequests.get(id);
    if (callback) {
      pendingRequests.delete(id);
      callback({
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
    for (const [id, callback] of pendingRequests) {
      callback({
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

  // Relay to native host
  try {
    const port = ensureNativeConnection();

    pendingRequests.set(message.id, sendResponse);

    port.postMessage({
      id: message.id,
      type: message.operation,
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
export { handleRuntimeMessage, isOriginAllowed, ALLOWED_ORIGINS, pendingRequests };
