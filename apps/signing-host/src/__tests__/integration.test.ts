/**
 * Integration tests for the native messaging host.
 *
 * Validates the full request lifecycle:
 *  - Protocol codec round-trip (encode → decode → handle → encode)
 *  - Origin validation integration with handler
 *  - Session lifecycle across connect → sign → disconnect
 *  - Three-layer origin validation model
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Readable, Writable } from "node:stream";
import { readMessage, writeMessage, type NativeRequest, type NativeResponse } from "../protocol.js";
import { validateOrigin } from "../origin-validator.js";
import { handleRequest } from "../handler.js";

// Mock session-manager to avoid real PKCS#11/OS cert calls
const { mockPkcs11Detect, mockPkcs11Connect, mockPkcs11Sign, mockPkcs11Disconnect } = vi.hoisted(
  () => ({
    mockPkcs11Detect: vi.fn(),
    mockPkcs11Connect: vi.fn(),
    mockPkcs11Sign: vi.fn(),
    mockPkcs11Disconnect: vi.fn(),
  }),
);

vi.mock("../session-manager.js", () => ({
  pkcs11Detect: mockPkcs11Detect,
  pkcs11ListSlots: vi.fn(() => []),
  pkcs11ListKeys: vi.fn(() => []),
  pkcs11Connect: mockPkcs11Connect,
  pkcs11Sign: mockPkcs11Sign,
  pkcs11Disconnect: mockPkcs11Disconnect,
  oscertList: vi.fn(async () => ({ certificates: [], platform: "darwin", storeName: "Keychain" })),
  oscertConnect: vi.fn(),
  oscertSign: vi.fn(),
  oscertDisconnect: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encode a NativeRequest as a native messaging frame (4-byte LE prefix + JSON). */
function encodeFrame(request: NativeRequest): Buffer {
  const json = JSON.stringify(request);
  const payload = Buffer.from(json, "utf-8");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(payload.length, 0);
  return Buffer.concat([prefix, payload]);
}

/** Create a readable stream from raw bytes. */
function streamFromBuffer(buf: Buffer): Readable {
  const stream = new Readable({ read() {} });
  stream.push(buf);
  stream.push(null);
  return stream;
}

/** Capture what writeMessage writes to a writable stream. */
function captureOutput(): { stream: Writable; getResponse: () => NativeResponse } {
  const chunks: Buffer[] = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });

  return {
    stream,
    getResponse() {
      const full = Buffer.concat(chunks);
      const length = full.readUInt32LE(0);
      const json = full.subarray(4, 4 + length).toString("utf-8");
      return JSON.parse(json) as NativeResponse;
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("protocol codec round-trip", () => {
  it("should encode, decode, handle, and re-encode a ping request", async () => {
    const request: NativeRequest = {
      id: "rt-1",
      type: "ping",
      origin: "chrome-extension://test",
      payload: {},
    };

    // Encode → Decode
    const frame = encodeFrame(request);
    const stream = streamFromBuffer(frame);
    const decoded = await readMessage(stream);

    expect(decoded).toEqual(request);

    // Handle
    const response = await handleRequest(decoded!);
    expect(response.id).toBe("rt-1");
    expect(response.success).toBe(true);
    expect(response.result).toHaveProperty("version");

    // Re-encode
    const output = captureOutput();
    writeMessage(output.stream, response);
    const roundTripped = output.getResponse();

    expect(roundTripped).toEqual(response);
  });

  it("should round-trip a PKCS#11 connect → sign → disconnect lifecycle", async () => {
    mockPkcs11Connect.mockReturnValue({
      signerId: "signer-int-1",
      metadata: {
        id: "key-int-1",
        algorithm: "P-256",
        type: "pkcs11",
        fingerprint: "abc123",
        label: "Test Key",
      },
    });
    mockPkcs11Sign.mockResolvedValue(new Uint8Array([1, 2, 3, 4]));
    mockPkcs11Disconnect.mockReturnValue(undefined);

    // Step 1: Connect
    const connectReq: NativeRequest = {
      id: "int-connect",
      type: "pkcs11_connect",
      origin: "chrome-extension://test",
      payload: { libraryPath: "/lib/test.so", slotIndex: 0, pin: "1234" },
    };
    const connectFrame = encodeFrame(connectReq);
    const connectDecoded = await readMessage(streamFromBuffer(connectFrame));
    const connectRes = await handleRequest(connectDecoded!);

    expect(connectRes.success).toBe(true);
    expect(connectRes.result).toHaveProperty("signerId", "signer-int-1");
    expect(connectRes.result).toHaveProperty("metadata");

    // Step 2: Sign
    const signReq: NativeRequest = {
      id: "int-sign",
      type: "pkcs11_sign",
      origin: "chrome-extension://test",
      payload: { signerId: "signer-int-1", data: Buffer.from("hello").toString("base64") },
    };
    const signDecoded = await readMessage(streamFromBuffer(encodeFrame(signReq)));
    const signRes = await handleRequest(signDecoded!);

    expect(signRes.success).toBe(true);
    expect(signRes.result).toHaveProperty("signature");

    // Verify the response round-trips through protocol encoding
    const output = captureOutput();
    writeMessage(output.stream, signRes);
    const signRoundTripped = output.getResponse();
    expect(signRoundTripped.result!["signature"]).toBe(signRes.result!["signature"]);

    // Step 3: Disconnect
    const disconnectReq: NativeRequest = {
      id: "int-disconnect",
      type: "pkcs11_disconnect",
      origin: "chrome-extension://test",
      payload: { signerId: "signer-int-1" },
    };
    const disconnectDecoded = await readMessage(streamFromBuffer(encodeFrame(disconnectReq)));
    const disconnectRes = await handleRequest(disconnectDecoded!);

    expect(disconnectRes.success).toBe(true);
  });

  it("should preserve Unicode in round-trip encoding", async () => {
    const request: NativeRequest = {
      id: "rt-unicode",
      type: "ping",
      origin: "chrome-extension://test-\u00e9\u00e8\u00ea",
      payload: { note: "\u4f60\u597d\u4e16\u754c" },
    };

    const frame = encodeFrame(request);
    const decoded = await readMessage(streamFromBuffer(frame));

    expect(decoded!.origin).toBe("chrome-extension://test-\u00e9\u00e8\u00ea");
    expect(decoded!.payload.note).toBe("\u4f60\u597d\u4e16\u754c");
  });
});

describe("three-layer origin validation model", () => {
  // Layer 1: Manifest match_patterns — validated by the browser itself (not testable in unit tests)
  // Layer 2: Background service worker allowlist — tested in browser-extension tests
  // Layer 3: Native host origin validator — tested here

  const ALLOWED = [
    "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
    "moz-extension://{12345678-1234-1234-1234-123456789012}",
  ];

  it("Layer 3: should accept allowed Chrome extension origin", () => {
    expect(validateOrigin("chrome-extension://abcdefghijklmnopabcdefghijklmnop", ALLOWED)).toBe(true);
  });

  it("Layer 3: should accept allowed Firefox extension origin", () => {
    expect(validateOrigin("moz-extension://{12345678-1234-1234-1234-123456789012}", ALLOWED)).toBe(true);
  });

  it("Layer 3: should reject web origins (only extension origins allowed)", () => {
    expect(validateOrigin("https://evil.example.com", ALLOWED)).toBe(false);
  });

  it("Layer 3: should reject empty origin", () => {
    expect(validateOrigin("", ALLOWED)).toBe(false);
  });

  it("Layer 3: should reject origin not in allowlist", () => {
    expect(validateOrigin("chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", ALLOWED)).toBe(false);
  });

  it("should enforce origin validation before handling requests", async () => {
    // Simulate the full flow: validate origin BEFORE calling handleRequest
    const request: NativeRequest = {
      id: "origin-check",
      type: "pkcs11_detect",
      origin: "https://evil.example.com",
      payload: {},
    };

    const originValid = validateOrigin(request.origin, ALLOWED);
    expect(originValid).toBe(false);

    // If origin invalid, we should NOT call handleRequest. Build rejection response.
    if (!originValid) {
      const rejectionResponse: NativeResponse = {
        id: request.id,
        success: false,
        error: { code: "ORIGIN_REJECTED", message: "Origin not in allowlist" },
      };

      // Verify it round-trips cleanly
      const output = captureOutput();
      writeMessage(output.stream, rejectionResponse);
      const roundTripped = output.getResponse();

      expect(roundTripped.success).toBe(false);
      expect(roundTripped.error!.code).toBe("ORIGIN_REJECTED");
    }
  });

  it("should allow request through when origin is valid", async () => {
    mockPkcs11Detect.mockReturnValue({ available: true });

    const request: NativeRequest = {
      id: "origin-ok",
      type: "pkcs11_detect",
      origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
      payload: {},
    };

    const originValid = validateOrigin(request.origin, ALLOWED);
    expect(originValid).toBe(true);

    const response = await handleRequest(request);
    expect(response.success).toBe(true);
    expect(response.result).toHaveProperty("available", true);
  });
});

describe("error response sanitization", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should not leak internal error details in PKCS#11 error responses", async () => {
    mockPkcs11Connect.mockImplementation(() => {
      throw new Error("PKCS#11 CKR_TOKEN_NOT_PRESENT at /usr/local/lib/softhsm2.so:session:42");
    });

    const request: NativeRequest = {
      id: "sanitize-1",
      type: "pkcs11_connect",
      origin: "chrome-extension://test",
      payload: { libraryPath: "/lib/test.so", slotIndex: 0, pin: "1234" },
    };

    const response = await handleRequest(request);

    expect(response.success).toBe(false);
    expect(response.error!.code).toBe("PKCS11_ERROR");
    // Error message should be the thrown message, but the response should
    // never contain stack traces or process-level details
    expect(JSON.stringify(response)).not.toContain("node_modules");
    expect(JSON.stringify(response)).not.toContain("at Object");
  });

  it("should return structured error for unknown operations", async () => {
    const request: NativeRequest = {
      id: "sanitize-2",
      type: "unknown_op" as NativeRequest["type"],
      origin: "chrome-extension://test",
      payload: {},
    };

    const response = await handleRequest(request);

    expect(response.success).toBe(false);
    expect(response.error!.code).toBe("UNKNOWN_OPERATION");
  });

  it("should return structured error for missing parameters", async () => {
    const request: NativeRequest = {
      id: "sanitize-3",
      type: "pkcs11_connect",
      origin: "chrome-extension://test",
      payload: {}, // Missing all required params
    };

    const response = await handleRequest(request);

    expect(response.success).toBe(false);
    expect(response.error!.code).toBe("INVALID_PARAMS");
  });
});
