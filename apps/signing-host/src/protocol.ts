/**
 * Native messaging protocol codec.
 *
 * Chrome/Firefox native messaging uses a binary framing protocol:
 *   [4-byte little-endian length][JSON payload]
 *
 * Messages are exchanged over stdin (requests from browser) and
 * stdout (responses to browser). Each message is a JSON object
 * prefixed by its byte length as a 32-bit unsigned little-endian integer.
 *
 * SECURITY INVARIANTS:
 *  - Maximum message size is enforced to prevent memory exhaustion.
 *  - No key material is ever included in protocol messages.
 *  - Error responses use sanitized messages (no internal paths/stack traces).
 */

import type { Readable, Writable } from "node:stream";

/** Maximum message size: 1 MiB (Chrome's native messaging limit). */
export const MAX_MESSAGE_SIZE = 1024 * 1024;

/** Length prefix size in bytes. */
const LENGTH_PREFIX_SIZE = 4;

// ---------------------------------------------------------------------------
// Operation types
// ---------------------------------------------------------------------------

export const OperationType = {
  PING: "ping",
  PKCS11_DETECT: "pkcs11_detect",
  PKCS11_LIST_SLOTS: "pkcs11_list_slots",
  PKCS11_LIST_KEYS: "pkcs11_list_keys",
  PKCS11_CONNECT: "pkcs11_connect",
  PKCS11_SIGN: "pkcs11_sign",
  PKCS11_DISCONNECT: "pkcs11_disconnect",
  OSCERT_LIST: "oscert_list",
  OSCERT_CONNECT: "oscert_connect",
  OSCERT_SIGN: "oscert_sign",
  OSCERT_DISCONNECT: "oscert_disconnect",
} as const;

export type OperationType = (typeof OperationType)[keyof typeof OperationType];

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/** Inbound request from the browser extension. */
export interface NativeRequest {
  /** Unique request identifier for correlation. */
  id: string;
  /** The operation to perform. */
  type: OperationType;
  /** The browser extension origin (validated against allowlist). */
  origin: string;
  /** Operation-specific payload. */
  payload: Record<string, unknown>;
}

/** Outbound response to the browser extension. */
export interface NativeResponse {
  /** Matches the request id. */
  id: string;
  /** Whether the operation succeeded. */
  success: boolean;
  /** Operation result (present when success is true). */
  result?: Record<string, unknown>;
  /** Error details (present when success is false). */
  error?: {
    code: string;
    message: string;
  };
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/**
 * Read a single native messaging frame from a readable stream.
 *
 * Reads the 4-byte little-endian length prefix, then reads exactly that
 * many bytes of JSON payload.
 *
 * @param stream - The readable stream (typically process.stdin).
 * @returns The parsed request, or null if the stream has ended.
 * @throws Error if the message exceeds MAX_MESSAGE_SIZE or is malformed.
 */
export function readMessage(stream: Readable): Promise<NativeRequest | null> {
  return new Promise((resolve, reject) => {
    /** Accumulated buffer for the current read. */
    let buffer = Buffer.alloc(0);
    /** Expected payload length (null until prefix is read). */
    let expectedLength: number | null = null;

    function cleanup() {
      stream.removeListener("readable", onReadable);
      stream.removeListener("end", onEnd);
      stream.removeListener("error", onError);
    }

    function onEnd() {
      cleanup();
      if (buffer.length === 0 && expectedLength === null) {
        // Clean stream close — no partial data
        resolve(null);
      } else {
        reject(new Error("Stream ended with incomplete message"));
      }
    }

    function onError(err: Error) {
      cleanup();
      reject(err);
    }

    function onReadable() {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        // Phase 1: read the length prefix
        if (expectedLength === null) {
          const needed = LENGTH_PREFIX_SIZE - buffer.length;
          const chunk = stream.read(needed) as Buffer | null;
          if (chunk === null) return; // Wait for more data

          buffer = Buffer.concat([buffer, chunk]);

          if (buffer.length < LENGTH_PREFIX_SIZE) return; // Still need more

          expectedLength = buffer.readUInt32LE(0);

          if (expectedLength > MAX_MESSAGE_SIZE) {
            cleanup();
            reject(
              new Error(
                `Message size ${expectedLength} exceeds maximum ${MAX_MESSAGE_SIZE}`,
              ),
            );
            return;
          }

          if (expectedLength === 0) {
            cleanup();
            reject(new Error("Message size is 0"));
            return;
          }

          // Reset buffer for the payload phase
          buffer = Buffer.alloc(0);
        }

        // Phase 2: read the JSON payload
        const payloadNeeded = expectedLength - buffer.length;
        const payloadChunk = stream.read(payloadNeeded) as Buffer | null;
        if (payloadChunk === null) return; // Wait for more data

        buffer = Buffer.concat([buffer, payloadChunk]);

        if (buffer.length < expectedLength) return; // Still need more

        // Complete message received
        cleanup();

        try {
          const json = buffer.toString("utf-8");
          const parsed = JSON.parse(json) as NativeRequest;
          resolve(parsed);
        } catch {
          reject(new Error("Failed to parse message as JSON"));
        }
        return;
      }
    }

    stream.on("readable", onReadable);
    stream.on("end", onEnd);
    stream.on("error", onError);

    // Try to read immediately in case data is already buffered
    onReadable();
  });
}

/**
 * Write a native messaging frame to a writable stream.
 *
 * Serialises the response as JSON, prepends the 4-byte little-endian
 * length prefix, and writes the frame to the stream.
 *
 * @param stream - The writable stream (typically process.stdout).
 * @param message - The response to send.
 * @throws Error if the serialised message exceeds MAX_MESSAGE_SIZE.
 */
export function writeMessage(stream: Writable, message: NativeResponse): void {
  const json = JSON.stringify(message);
  const payload = Buffer.from(json, "utf-8");

  if (payload.length > MAX_MESSAGE_SIZE) {
    throw new Error(
      `Response size ${payload.length} exceeds maximum ${MAX_MESSAGE_SIZE}`,
    );
  }

  const prefix = Buffer.alloc(LENGTH_PREFIX_SIZE);
  prefix.writeUInt32LE(payload.length, 0);

  stream.write(prefix);
  stream.write(payload);
}
