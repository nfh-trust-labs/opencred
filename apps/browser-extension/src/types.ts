/**
 * Shared types for the browser extension message protocol.
 *
 * Messages flow: Web Page <-> Content Script <-> Background <-> Native Host
 *
 * The content script relays postMessage events from the web page to
 * the background service worker via chrome.runtime.sendMessage, and
 * the background relays them to the native host via connectNative.
 */

/** The native messaging host name (must match the installed manifest). */
export const NATIVE_HOST_NAME = "com.opencred.signing";

/** Extension version. Returned by detect requests. */
export const EXTENSION_VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Web page <-> Content script messages (via window.postMessage)
// ---------------------------------------------------------------------------

/** Message type sent from the web page to the content script. */
export const PAGE_REQUEST_TYPE = "opencred-signing-request";

/** Message type sent from the content script back to the web page. */
export const PAGE_RESPONSE_TYPE = "opencred-signing-response";

/** Message type for extension detection from the web page. */
export const PAGE_DETECT_TYPE = "opencred-signing-detect";

/** Message type for extension detection response. */
export const PAGE_DETECT_RESPONSE_TYPE = "opencred-signing-detect-response";

export interface PageRequest {
  type: typeof PAGE_REQUEST_TYPE;
  id: string;
  operation: string;
  payload: Record<string, unknown>;
}

export interface PageResponse {
  type: typeof PAGE_RESPONSE_TYPE;
  id: string;
  success: boolean;
  result?: Record<string, unknown>;
  error?: { code: string; message: string };
}

export interface PageDetectRequest {
  type: typeof PAGE_DETECT_TYPE;
}

export interface PageDetectResponse {
  type: typeof PAGE_DETECT_RESPONSE_TYPE;
  available: boolean;
  version: string;
}

// ---------------------------------------------------------------------------
// Content script <-> Background messages (via chrome.runtime.sendMessage)
// ---------------------------------------------------------------------------

export interface RuntimeRequest {
  action: "signing-request";
  id: string;
  operation: string;
  origin: string;
  payload: Record<string, unknown>;
}

export interface RuntimeResponse {
  id: string;
  success: boolean;
  result?: Record<string, unknown>;
  error?: { code: string; message: string };
}
