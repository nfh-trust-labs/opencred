/**
 * QR code generator for Verifiable Credentials.
 *
 * Uses PixelPass (@mosip/pixelpass) to compress credential data before
 * encoding into QR codes. The compression pipeline is:
 *
 *   JSON → CBOR encode → zlib compress (level 9) → Base45 encode
 *
 * This dramatically reduces the QR payload size — a 3KB credential
 * typically compresses to under 1KB, fitting comfortably in a QR code.
 *
 * QR data is prefixed with "OPENCRED1:" so decoders can identify the
 * format and apply the correct decompression pipeline.
 *
 * Works completely offline — no network requests.
 */

import { createRequire } from "node:module";
import QRCode from "qrcode";
import type { VerifiableCredential } from "@opencred/vc-core";
import { ValidationError } from "@opencred/shared";

// PixelPass is a CJS module — use createRequire for ESM compatibility
const require = createRequire(import.meta.url);
const pixelpass = require("@mosip/pixelpass") as {
  generateQRData: (data: string, header?: string) => string;
  decode: (data: string) => string;
};

/** Header prefix for OpenCred QR codes. */
const QR_HEADER = "OPENCRED1:";

/**
 * Compress a credential JSON string using the PixelPass pipeline.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns Compressed Base45 string with OPENCRED1: header.
 */
export function compressCredentialForQr(credential: VerifiableCredential): string {
  const json = JSON.stringify(credential);
  return pixelpass.generateQRData(json, QR_HEADER);
}

/**
 * Decode a PixelPass-compressed QR string back to credential JSON.
 *
 * Strips the OPENCRED1: header if present, then runs the reverse
 * pipeline: Base45 decode → zlib decompress → CBOR decode → JSON.
 *
 * @param qrData - The raw string scanned from a QR code.
 * @returns The decompressed credential JSON string.
 * @throws If the data cannot be decoded.
 */
export function decodeQrData(qrData: string): string {
  const data = qrData.startsWith(QR_HEADER) ? qrData.slice(QR_HEADER.length) : qrData;
  return pixelpass.decode(data);
}

/**
 * Resolve the QR payload for either a JSON-LD credential (PixelPass
 * compress + `OPENCRED1:` prefix) or a compact JWT/SD-JWT token
 * (embed verbatim — already compact, and verifiers expect the raw token).
 *
 * Embedding a compact token verbatim is intentional:
 *
 *   1. JWTs are already base64url-encoded and small (a few hundred bytes
 *      for typical bootcamp credentials), so PixelPass compression
 *      doesn't help and would force scanners to decompress before
 *      verifying.
 *   2. The QR scanner side calls into the verification engine, which
 *      auto-detects compact-JWT input via `detectCredentialInputFormat`
 *      and runs a real cryptographic check. Wrapping the JWT in another
 *      envelope would break that path.
 */
function resolveQrPayload(credential: VerifiableCredential | string): string {
  if (typeof credential === "string") {
    return credential;
  }
  return compressCredentialForQr(credential);
}

/**
 * Build a precise capacity-exceeded error message for a QR generation
 * failure. The compressed-vs-verbatim distinction matters: telling a
 * caller their compact token was rejected "even after compression"
 * misleads them — no compression ran.
 */
function qrCapacityError(credential: VerifiableCredential | string, err: unknown): string {
  const detail =
    typeof credential === "string"
      ? "Compact token exceeds QR data capacity."
      : "Credential too large for QR code even after compression.";
  const cause = err instanceof Error ? err.message : "unknown error";
  return `${detail} Consider using JSON export instead. (${cause})`;
}

/**
 * Generate a QR code from a credential as a PNG data URL.
 *
 * Accepts either a JSON-LD VerifiableCredential (compressed via
 * PixelPass) or a compact JWT/SD-JWT token (embedded verbatim).
 *
 * @returns A PNG data URL (base64-encoded).
 * @throws {ValidationError} if the data still exceeds QR capacity.
 */
export async function generateQrPng(credential: VerifiableCredential | string): Promise<string> {
  const payload = resolveQrPayload(credential);

  try {
    return await QRCode.toDataURL(payload, {
      errorCorrectionLevel: "L",
      type: "image/png",
      margin: 2,
      width: 400,
    });
  } catch (err) {
    throw new ValidationError(qrCapacityError(credential, err));
  }
}

/**
 * Generate a QR code from a credential as an SVG string.
 *
 * Accepts either a JSON-LD VerifiableCredential (compressed via
 * PixelPass) or a compact JWT/SD-JWT token (embedded verbatim).
 *
 * @returns An SVG string.
 * @throws {ValidationError} if the data still exceeds QR capacity.
 */
export async function generateQrSvg(credential: VerifiableCredential | string): Promise<string> {
  const payload = resolveQrPayload(credential);

  try {
    return await QRCode.toString(payload, {
      errorCorrectionLevel: "L",
      type: "svg",
      margin: 2,
      width: 400,
    });
  } catch (err) {
    throw new ValidationError(qrCapacityError(credential, err));
  }
}

/**
 * Generate a QR code from a credential as a PNG Buffer.
 *
 * Accepts either a JSON-LD VerifiableCredential (compressed via
 * PixelPass) or a compact JWT/SD-JWT token (embedded verbatim).
 *
 * @returns A PNG Buffer.
 * @throws {ValidationError} if the data still exceeds QR capacity.
 */
export async function generateQrBuffer(credential: VerifiableCredential | string): Promise<Buffer> {
  const payload = resolveQrPayload(credential);

  try {
    return await QRCode.toBuffer(payload, {
      errorCorrectionLevel: "L",
      type: "png",
      margin: 2,
      width: 400,
    });
  } catch (err) {
    throw new ValidationError(qrCapacityError(credential, err));
  }
}
