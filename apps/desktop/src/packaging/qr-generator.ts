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
 * Generate a QR code from a VerifiableCredential as a PNG data URL.
 *
 * The credential is compressed via PixelPass before QR encoding.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns A PNG data URL (base64-encoded).
 * @throws {ValidationError} if the compressed data still exceeds QR capacity.
 */
export async function generateQrPng(credential: VerifiableCredential): Promise<string> {
  const compressed = compressCredentialForQr(credential);

  try {
    return await QRCode.toDataURL(compressed, {
      errorCorrectionLevel: "L",
      type: "image/png",
      margin: 2,
      width: 400,
    });
  } catch (err) {
    throw new ValidationError(
      `Credential too large for QR code even after compression. Consider using JSON export instead. (${err instanceof Error ? err.message : "unknown error"})`,
    );
  }
}

/**
 * Generate a QR code from a VerifiableCredential as an SVG string.
 *
 * The credential is compressed via PixelPass before QR encoding.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns An SVG string.
 * @throws {ValidationError} if the compressed data still exceeds QR capacity.
 */
export async function generateQrSvg(credential: VerifiableCredential): Promise<string> {
  const compressed = compressCredentialForQr(credential);

  try {
    return await QRCode.toString(compressed, {
      errorCorrectionLevel: "L",
      type: "svg",
      margin: 2,
      width: 400,
    });
  } catch (err) {
    throw new ValidationError(
      `Credential too large for QR code even after compression. Consider using JSON export instead. (${err instanceof Error ? err.message : "unknown error"})`,
    );
  }
}

/**
 * Generate a QR code from a VerifiableCredential as a PNG Buffer.
 *
 * The credential is compressed via PixelPass before QR encoding.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns A PNG Buffer.
 * @throws {ValidationError} if the compressed data still exceeds QR capacity.
 */
export async function generateQrBuffer(credential: VerifiableCredential): Promise<Buffer> {
  const compressed = compressCredentialForQr(credential);

  try {
    return await QRCode.toBuffer(compressed, {
      errorCorrectionLevel: "L",
      type: "png",
      margin: 2,
      width: 400,
    });
  } catch (err) {
    throw new ValidationError(
      `Credential too large for QR code even after compression. Consider using JSON export instead. (${err instanceof Error ? err.message : "unknown error"})`,
    );
  }
}
