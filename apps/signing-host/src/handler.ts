/**
 * Request handler for the native messaging host.
 *
 * Dispatches incoming requests by operation type to the appropriate handler.
 * Returns NativeResponse objects that are sent back to the browser extension.
 *
 * SECURITY INVARIANTS:
 *  - Error responses never leak internal paths, stack traces, or key material.
 *  - All handlers validate their inputs before proceeding.
 *  - Unknown operation types return a structured error, not an exception.
 *  - PINs are passed through to the session manager and never stored here.
 */

import { OperationType, type NativeRequest, type NativeResponse } from "./protocol.js";
import {
  pkcs11Detect,
  pkcs11ListSlots,
  pkcs11ListKeys,
  pkcs11Connect,
  pkcs11Sign,
  pkcs11Disconnect,
  oscertList,
  oscertConnect,
  oscertSign,
  oscertDisconnect,
} from "./session-manager.js";

/** The native host version. Returned by the ping handler. */
const HOST_VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function requireString(
  request: NativeRequest,
  payload: Record<string, unknown>,
  name: string,
): string | NativeResponse {
  const value = payload[name];
  if (!value || typeof value !== "string") {
    return {
      id: request.id,
      success: false,
      error: { code: "INVALID_PARAMS", message: `Missing required parameter: ${name}` },
    };
  }
  return value;
}

function requireNumber(
  request: NativeRequest,
  payload: Record<string, unknown>,
  name: string,
): number | NativeResponse {
  const value = payload[name];
  if (typeof value !== "number") {
    return {
      id: request.id,
      success: false,
      error: { code: "INVALID_PARAMS", message: `Missing required parameter: ${name}` },
    };
  }
  return value;
}

function isErrorResponse(value: unknown): value is NativeResponse {
  return typeof value === "object" && value !== null && "success" in value;
}

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

/**
 * Handle an incoming native messaging request.
 *
 * Dispatches to the appropriate handler based on request.type.
 * Returns a fully-formed NativeResponse.
 *
 * @param request - The validated incoming request.
 * @returns The response to send back to the browser extension.
 */
export async function handleRequest(request: NativeRequest): Promise<NativeResponse> {
  switch (request.type) {
    case OperationType.PING:
      return handlePing(request);

    case OperationType.PKCS11_DETECT:
      return handlePkcs11Detect(request);
    case OperationType.PKCS11_LIST_SLOTS:
      return handlePkcs11ListSlots(request);
    case OperationType.PKCS11_LIST_KEYS:
      return handlePkcs11ListKeys(request);
    case OperationType.PKCS11_CONNECT:
      return handlePkcs11Connect(request);
    case OperationType.PKCS11_SIGN:
      return handlePkcs11Sign(request);
    case OperationType.PKCS11_DISCONNECT:
      return handlePkcs11Disconnect(request);

    case OperationType.OSCERT_LIST:
      return handleOscertList(request);
    case OperationType.OSCERT_CONNECT:
      return handleOscertConnect(request);
    case OperationType.OSCERT_SIGN:
      return handleOscertSign(request);
    case OperationType.OSCERT_DISCONNECT:
      return handleOscertDisconnect(request);

    default:
      return {
        id: request.id,
        success: false,
        error: {
          code: "UNKNOWN_OPERATION",
          message: `Unknown operation type: ${request.type}`,
        },
      };
  }
}

// ---------------------------------------------------------------------------
// Ping
// ---------------------------------------------------------------------------

function handlePing(request: NativeRequest): NativeResponse {
  return {
    id: request.id,
    success: true,
    result: {
      version: HOST_VERSION,
      platform: process.platform,
    },
  };
}

// ---------------------------------------------------------------------------
// PKCS#11 handlers
// ---------------------------------------------------------------------------

function handlePkcs11Detect(request: NativeRequest): NativeResponse {
  try {
    const result = pkcs11Detect();
    return {
      id: request.id,
      success: true,
      result: { available: result.available },
    };
  } catch {
    return {
      id: request.id,
      success: true,
      result: { available: false },
    };
  }
}

function handlePkcs11ListSlots(request: NativeRequest): NativeResponse {
  const libraryPath = requireString(request, request.payload, "libraryPath");
  if (isErrorResponse(libraryPath)) return libraryPath;

  try {
    const slots = pkcs11ListSlots(libraryPath);
    return { id: request.id, success: true, result: { slots } };
  } catch (error) {
    return {
      id: request.id,
      success: false,
      error: { code: "PKCS11_ERROR", message: getErrorMessage(error, "Failed to list PKCS#11 slots") },
    };
  }
}

function handlePkcs11ListKeys(request: NativeRequest): NativeResponse {
  const libraryPath = requireString(request, request.payload, "libraryPath");
  if (isErrorResponse(libraryPath)) return libraryPath;
  const slotIndex = requireNumber(request, request.payload, "slotIndex");
  if (isErrorResponse(slotIndex)) return slotIndex;
  const pin = requireString(request, request.payload, "pin");
  if (isErrorResponse(pin)) return pin;

  try {
    const keys = pkcs11ListKeys(libraryPath, slotIndex, pin);
    const serializedKeys = keys.map((k) => ({
      label: k.label,
      id: k.id,
      keyType: k.keyType,
      hasPublicKey: k.hasPublicKey,
    }));
    return { id: request.id, success: true, result: { keys: serializedKeys } };
  } catch (error) {
    return {
      id: request.id,
      success: false,
      error: { code: "PKCS11_ERROR", message: getErrorMessage(error, "Failed to list keys") },
    };
  }
}

function handlePkcs11Connect(request: NativeRequest): NativeResponse {
  const { keyId, label } = request.payload;
  const libraryPath = requireString(request, request.payload, "libraryPath");
  if (isErrorResponse(libraryPath)) return libraryPath;
  const slotIndex = requireNumber(request, request.payload, "slotIndex");
  if (isErrorResponse(slotIndex)) return slotIndex;
  const pin = requireString(request, request.payload, "pin");
  if (isErrorResponse(pin)) return pin;

  try {
    const result = pkcs11Connect(
      libraryPath,
      slotIndex,
      pin,
      typeof keyId === "string" ? keyId : undefined,
      typeof label === "string" ? label : undefined,
    );

    return {
      id: request.id,
      success: true,
      result: {
        signerId: result.signerId,
        metadata: result.metadata,
      },
    };
  } catch (error) {
    return {
      id: request.id,
      success: false,
      error: { code: "PKCS11_ERROR", message: getErrorMessage(error, "Failed to connect to PKCS#11 token") },
    };
  }
}

async function handlePkcs11Sign(request: NativeRequest): Promise<NativeResponse> {
  return handleSign(request, pkcs11Sign, "PKCS11_ERROR");
}

function handlePkcs11Disconnect(request: NativeRequest): NativeResponse {
  return handleDisconnect(request, pkcs11Disconnect, "PKCS11_ERROR");
}

// ---------------------------------------------------------------------------
// OS cert handlers
// ---------------------------------------------------------------------------

async function handleOscertList(request: NativeRequest): Promise<NativeResponse> {
  const { platform } = request.payload;

  try {
    const result = await oscertList(
      typeof platform === "string" ? (platform as "darwin" | "win32" | "linux") : undefined,
    );

    const safeCerts = result.certificates.map((c) => ({
      id: c.id,
      subject: c.subject,
      issuer: c.issuer,
      serialNumber: c.serialNumber,
      validFrom: c.validFrom,
      validUntil: c.validUntil,
      keyAlgorithm: c.keyAlgorithm,
      isExportable: c.isExportable,
      thumbprint: c.thumbprint,
    }));

    return {
      id: request.id,
      success: true,
      result: {
        certificates: safeCerts,
        platform: result.platform,
        storeName: result.storeName,
      },
    };
  } catch (error) {
    return {
      id: request.id,
      success: false,
      error: { code: "OSCERT_ERROR", message: getErrorMessage(error, "Failed to list OS certificates") },
    };
  }
}

async function handleOscertConnect(request: NativeRequest): Promise<NativeResponse> {
  const { platform, label } = request.payload;
  const certificateId = requireString(request, request.payload, "certificateId");
  if (isErrorResponse(certificateId)) return certificateId;

  try {
    const result = await oscertConnect(
      certificateId,
      typeof platform === "string" ? (platform as "darwin" | "win32" | "linux") : undefined,
      typeof label === "string" ? label : undefined,
    );

    return {
      id: request.id,
      success: true,
      result: {
        signerId: result.signerId,
        metadata: result.metadata,
      },
    };
  } catch (error) {
    return {
      id: request.id,
      success: false,
      error: { code: "OSCERT_ERROR", message: getErrorMessage(error, "Failed to connect to OS certificate") },
    };
  }
}

async function handleOscertSign(request: NativeRequest): Promise<NativeResponse> {
  return handleSign(request, oscertSign, "OSCERT_ERROR");
}

function handleOscertDisconnect(request: NativeRequest): NativeResponse {
  return handleDisconnect(request, oscertDisconnect, "OSCERT_ERROR");
}

// ---------------------------------------------------------------------------
// Shared sign/disconnect handlers
// ---------------------------------------------------------------------------

async function handleSign(
  request: NativeRequest,
  signFn: (signerId: string, data: Uint8Array) => Promise<Uint8Array>,
  errorCode: string,
): Promise<NativeResponse> {
  const signerId = requireString(request, request.payload, "signerId");
  if (isErrorResponse(signerId)) return signerId;
  const data = requireString(request, request.payload, "data");
  if (isErrorResponse(data)) return data;

  let dataBytes: Uint8Array;
  try {
    dataBytes = new Uint8Array(Buffer.from(data, "base64"));
  } catch {
    return {
      id: request.id,
      success: false,
      error: { code: "INVALID_PARAMS", message: "Invalid base64 data" },
    };
  }

  try {
    const signature = await signFn(signerId, dataBytes);
    return {
      id: request.id,
      success: true,
      result: { signature: Buffer.from(signature).toString("base64") },
    };
  } catch (error) {
    return {
      id: request.id,
      success: false,
      error: { code: errorCode, message: getErrorMessage(error, "Signing operation failed") },
    };
  }
}

function handleDisconnect(
  request: NativeRequest,
  disconnectFn: (signerId: string) => void,
  errorCode: string,
): NativeResponse {
  const signerId = requireString(request, request.payload, "signerId");
  if (isErrorResponse(signerId)) return signerId;

  try {
    disconnectFn(signerId);
    return { id: request.id, success: true, result: {} };
  } catch (error) {
    return {
      id: request.id,
      success: false,
      error: { code: errorCode, message: getErrorMessage(error, "Failed to disconnect") },
    };
  }
}
