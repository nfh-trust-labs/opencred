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
 * **No header / prefix is added to the payload.** Bare PixelPass output
 * matches `@mosip/pixelpass`'s own default (`generateQRData(data)` with
 * no second arg) and is what the MOSIP/Inji verifier toolchain — and any
 * other consumer that calls `pixelpass.decode()` directly — expects.
 *
 * Works completely offline — no network requests.
 */

import QRCode from "qrcode";
import type { VerifiableCredential } from "@opencred/vc-core";
import { ValidationError, encodePixelPass, decodePixelPass } from "@opencred/shared";

/**
 * Compress a credential JSON string using the PixelPass pipeline.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns Bare PixelPass-compressed Base45 string (no header).
 */
export function compressCredentialForQr(credential: VerifiableCredential): string {
  return encodePixelPass(JSON.stringify(credential));
}

/**
 * Decode a PixelPass-compressed QR string back to credential JSON.
 *
 * Runs the reverse pipeline: Base45 decode → zlib decompress → CBOR
 * decode → JSON.
 *
 * @param qrData - The raw string scanned from a QR code.
 * @returns The decompressed credential JSON string.
 * @throws If the data cannot be decoded.
 */
export function decodeQrData(qrData: string): string {
  return decodePixelPass(qrData);
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
