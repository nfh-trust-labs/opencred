/**
 * Native messaging host entry point.
 *
 * Runs a stdin/stdout message loop using the native messaging protocol.
 * Each request is validated (origin check) then dispatched to the handler.
 *
 * SECURITY INVARIANTS:
 *  - Origin is validated on every request before any processing.
 *  - Error responses are sanitized — no internal paths or stack traces.
 *  - Graceful shutdown on SIGTERM/SIGINT.
 *  - No key material is ever logged or included in error messages.
 */

import { readMessage, writeMessage, type NativeResponse } from "./protocol.js";
import { validateOrigin, DEFAULT_ALLOWED_ORIGINS } from "./origin-validator.js";
import { handleRequest } from "./handler.js";

/** Whether the host is shutting down. */
let shuttingDown = false;

/**
 * Build an origin allowlist from the default list and the
 * OPENCRED_ALLOWED_ORIGINS environment variable (comma-separated).
 */
function buildAllowlist(): string[] {
  const envOrigins = process.env["OPENCRED_ALLOWED_ORIGINS"];
  const extra = envOrigins
    ? envOrigins.split(",").map((o) => o.trim()).filter((o) => o.length > 0)
    : [];
  return [...DEFAULT_ALLOWED_ORIGINS, ...extra];
}

/**
 * Write a sanitized error response for unhandled failures.
 * Never includes internal details.
 */
function writeErrorResponse(requestId: string, code: string, message: string): void {
  const response: NativeResponse = {
    id: requestId,
    success: false,
    error: { code, message },
  };
  writeMessage(process.stdout, response);
}

/**
 * Main message loop. Reads requests from stdin, validates origin,
 * dispatches to handler, writes response to stdout.
 */
async function main(): Promise<void> {
  const allowlist = buildAllowlist();

  // Set stdin to binary/flowing mode for native messaging
  process.stdin.resume();

  while (!shuttingDown) {
    let request;
    try {
      request = await readMessage(process.stdin);
    } catch {
      // Stream error or malformed message — nothing to respond to
      break;
    }

    // null means stdin closed (browser disconnected)
    if (request === null) {
      break;
    }

    // Validate required fields
    if (!request.id || typeof request.id !== "string") {
      // Cannot respond without an id — skip
      continue;
    }

    if (!request.type || typeof request.type !== "string") {
      writeErrorResponse(request.id, "INVALID_REQUEST", "Missing or invalid 'type' field");
      continue;
    }

    // Validate origin on every request
    if (!validateOrigin(request.origin, allowlist)) {
      writeErrorResponse(request.id, "ORIGIN_DENIED", "Origin is not in the allowlist");
      continue;
    }

    // Dispatch to handler
    try {
      const response = await handleRequest(request);
      writeMessage(process.stdout, response);
    } catch {
      // Catch-all: never leak internal error details
      writeErrorResponse(request.id, "INTERNAL_ERROR", "An unexpected error occurred");
    }
  }
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

function shutdown(): void {
  if (shuttingDown) return;
  shuttingDown = true;
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// Start the message loop
main().catch(() => {
  process.exit(1);
});
