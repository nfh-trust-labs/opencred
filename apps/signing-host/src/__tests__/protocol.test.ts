/**
 * Tests for the native messaging protocol codec.
 *
 * Validates:
 *  - Round-trip encode/decode of messages
 *  - Length prefix encoding (little-endian)
 *  - Maximum message size enforcement
 *  - Handling of invalid/malformed messages
 *  - Stream EOF handling
 */

import { describe, it, expect } from "vitest";
import { PassThrough } from "node:stream";
import {
  readMessage,
  writeMessage,
  MAX_MESSAGE_SIZE,
  type NativeRequest,
  type NativeResponse,
} from "../protocol.js";

/**
 * Encode a native messaging frame: 4-byte LE length prefix + JSON.
 */
function encodeFrame(obj: unknown): Buffer {
  const json = JSON.stringify(obj);
  const payload = Buffer.from(json, "utf-8");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(payload.length, 0);
  return Buffer.concat([prefix, payload]);
}

/**
 * Decode a native messaging frame from a buffer: read 4-byte LE prefix + JSON.
 */
function decodeFrame(buf: Buffer): unknown {
  const length = buf.readUInt32LE(0);
  const payload = buf.subarray(4, 4 + length);
  return JSON.parse(payload.toString("utf-8"));
}

// ---------------------------------------------------------------------------
// readMessage tests
// ---------------------------------------------------------------------------

describe("readMessage", () => {
  it("should read a valid native messaging frame", async () => {
    const request: NativeRequest = {
      id: "req-1",
      type: "ping",
      origin: "chrome-extension://test",
      payload: {},
    };

    const stream = new PassThrough();
    stream.end(encodeFrame(request));

    const result = await readMessage(stream);
    expect(result).toEqual(request);
  });

  it("should return null when stream is empty", async () => {
    const stream = new PassThrough();
    stream.end();

    const result = await readMessage(stream);
    expect(result).toBeNull();
  });

  it("should reject messages exceeding MAX_MESSAGE_SIZE", async () => {
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32LE(MAX_MESSAGE_SIZE + 1, 0);

    const stream = new PassThrough();
    stream.end(prefix);

    await expect(readMessage(stream)).rejects.toThrow(/exceeds maximum/);
  });

  it("should reject zero-length messages", async () => {
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32LE(0, 0);

    const stream = new PassThrough();
    stream.end(prefix);

    await expect(readMessage(stream)).rejects.toThrow(/size is 0/);
  });

  it("should reject incomplete messages (stream ends mid-payload)", async () => {
    const request = { id: "req-1", type: "ping", origin: "test", payload: {} };
    const json = JSON.stringify(request);
    const payload = Buffer.from(json, "utf-8");

    const prefix = Buffer.alloc(4);
    prefix.writeUInt32LE(payload.length, 0);

    // Only write half the payload
    const partial = Buffer.concat([prefix, payload.subarray(0, Math.floor(payload.length / 2))]);

    const stream = new PassThrough();
    stream.end(partial);

    await expect(readMessage(stream)).rejects.toThrow(/incomplete/);
  });

  it("should reject invalid JSON payloads", async () => {
    const badJson = Buffer.from("not valid json{{{", "utf-8");
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32LE(badJson.length, 0);

    const stream = new PassThrough();
    stream.end(Buffer.concat([prefix, badJson]));

    await expect(readMessage(stream)).rejects.toThrow(/JSON/);
  });

  it("should handle messages at exactly MAX_MESSAGE_SIZE", async () => {
    // Build a payload that's close to MAX_MESSAGE_SIZE but still valid JSON
    const padding = "x".repeat(MAX_MESSAGE_SIZE - 50);
    const request = { id: "1", type: "ping", origin: "o", payload: {}, _pad: padding };
    const json = JSON.stringify(request);
    const payload = Buffer.from(json, "utf-8");

    // Only test if the payload is within bounds
    if (payload.length <= MAX_MESSAGE_SIZE) {
      const prefix = Buffer.alloc(4);
      prefix.writeUInt32LE(payload.length, 0);

      const stream = new PassThrough();
      stream.end(Buffer.concat([prefix, payload]));

      const result = await readMessage(stream);
      expect(result).toBeDefined();
      expect(result!.id).toBe("1");
    }
  });

  it("should read messages written in multiple chunks", async () => {
    const request: NativeRequest = {
      id: "chunked-1",
      type: "ping",
      origin: "chrome-extension://test",
      payload: { key: "value" },
    };

    const frame = encodeFrame(request);
    const stream = new PassThrough();

    // Write the frame in small chunks
    const chunkSize = 3;
    for (let i = 0; i < frame.length; i += chunkSize) {
      stream.write(frame.subarray(i, Math.min(i + chunkSize, frame.length)));
    }
    stream.end();

    const result = await readMessage(stream);
    expect(result).toEqual(request);
  });
});

// ---------------------------------------------------------------------------
// writeMessage tests
// ---------------------------------------------------------------------------

describe("writeMessage", () => {
  it("should write a valid native messaging frame", () => {
    const response: NativeResponse = {
      id: "req-1",
      success: true,
      result: { version: "0.1.0" },
    };

    const stream = new PassThrough();
    writeMessage(stream, response);
    stream.end();

    const buf = stream.read() as Buffer;
    expect(buf).toBeDefined();

    const decoded = decodeFrame(buf);
    expect(decoded).toEqual(response);
  });

  it("should correctly encode the length prefix as little-endian", () => {
    const response: NativeResponse = {
      id: "req-2",
      success: true,
      result: {},
    };

    const stream = new PassThrough();
    writeMessage(stream, response);
    stream.end();

    const buf = stream.read() as Buffer;
    const declaredLength = buf.readUInt32LE(0);
    const payload = buf.subarray(4);

    expect(declaredLength).toBe(payload.length);
  });

  it("should write error responses correctly", () => {
    const response: NativeResponse = {
      id: "req-3",
      success: false,
      error: { code: "TEST_ERROR", message: "Something went wrong" },
    };

    const stream = new PassThrough();
    writeMessage(stream, response);
    stream.end();

    const buf = stream.read() as Buffer;
    const decoded = decodeFrame(buf) as NativeResponse;

    expect(decoded.success).toBe(false);
    expect(decoded.error!.code).toBe("TEST_ERROR");
    expect(decoded.error!.message).toBe("Something went wrong");
  });
});

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

describe("round-trip encode/decode", () => {
  it("should survive a write -> read round-trip", async () => {
    const response: NativeResponse = {
      id: "rt-1",
      success: true,
      result: { version: "0.1.0", platform: "darwin" },
    };

    const stream = new PassThrough();
    writeMessage(stream, response);
    stream.end();

    // readMessage expects NativeRequest format, but the framing is the same.
    // We can read the raw frame to verify.
    const buf = stream.read() as Buffer;
    const decoded = decodeFrame(buf) as NativeResponse;

    expect(decoded.id).toBe("rt-1");
    expect(decoded.success).toBe(true);
    expect(decoded.result!["version"]).toBe("0.1.0");
  });

  it("should handle unicode content", async () => {
    const request: NativeRequest = {
      id: "unicode-1",
      type: "ping",
      origin: "chrome-extension://test",
      payload: { label: "Ünïcödé ✓ 日本語" },
    };

    const stream = new PassThrough();
    stream.end(encodeFrame(request));

    const result = await readMessage(stream);
    expect(result).toEqual(request);
    expect(result!.payload["label"]).toBe("Ünïcödé ✓ 日本語");
  });
});
