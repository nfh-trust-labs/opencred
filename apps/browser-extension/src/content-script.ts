/**
 * Content script injected into web pages matching the OpenCred origin.
 *
 * Relays signing requests between the web page and the background
 * service worker. The content script acts as a bridge:
 *
 *   Web page (postMessage) -> Content script -> Background (runtime.sendMessage)
 *   Background (response)  -> Content script -> Web page (postMessage)
 *
 * Also handles extension detection requests so the web page can check
 * if the OpenCred signing extension is installed.
 *
 * SECURITY:
 *  - Only processes messages with the correct type field.
 *  - Passes the page origin to the background for validation.
 *  - Does not access or modify page DOM.
 */

import {
  PAGE_REQUEST_TYPE,
  PAGE_RESPONSE_TYPE,
  PAGE_DETECT_TYPE,
  PAGE_DETECT_RESPONSE_TYPE,
  EXTENSION_VERSION,
  type PageRequest,
  type PageResponse,
  type RuntimeRequest,
  type RuntimeResponse,
} from "./types.js";

/**
 * Handle incoming window.postMessage events.
 */
function handleMessage(event: MessageEvent): void {
  // Only accept messages from the same window
  if (event.source !== window) return;

  const data = event.data;
  if (!data || typeof data !== "object") return;

  if (data.type === PAGE_DETECT_TYPE) {
    handleDetect();
    return;
  }

  if (data.type === PAGE_REQUEST_TYPE) {
    handleSigningRequest(data as PageRequest);
    return;
  }
}

/**
 * Respond to extension detection requests.
 */
function handleDetect(): void {
  window.postMessage(
    {
      type: PAGE_DETECT_RESPONSE_TYPE,
      available: true,
      version: EXTENSION_VERSION,
    },
    "*",
  );
}

/**
 * Relay a signing request to the background service worker.
 */
function handleSigningRequest(request: PageRequest): void {
  if (!request.id || !request.operation) return;

  const runtimeMessage: RuntimeRequest = {
    action: "signing-request",
    id: request.id,
    operation: request.operation,
    origin: window.location.origin,
    payload: request.payload ?? {},
  };

  chrome.runtime.sendMessage(runtimeMessage, (response: RuntimeResponse | undefined) => {
    if (chrome.runtime.lastError) {
      const errorResponse: PageResponse = {
        type: PAGE_RESPONSE_TYPE,
        id: request.id,
        success: false,
        error: {
          code: "EXTENSION_ERROR",
          message: "Failed to communicate with extension background",
        },
      };
      window.postMessage(errorResponse, "*");
      return;
    }

    if (response) {
      const pageResponse: PageResponse = {
        type: PAGE_RESPONSE_TYPE,
        id: response.id,
        success: response.success,
        result: response.result,
        error: response.error,
      };
      window.postMessage(pageResponse, "*");
    }
  });
}

// Register the message listener
window.addEventListener("message", handleMessage);
