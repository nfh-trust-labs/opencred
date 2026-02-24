/**
 * QR code generator for Verifiable Credentials.
 *
 * Generates QR codes from VCs using the qrcode npm package.
 * Works completely offline -- no network requests.
 *
 * The QR code encodes the JSON-LD credential as a string. For large
 * credentials that exceed QR capacity, the generator returns an error
 * rather than silently truncating data.
 */

import QRCode from "qrcode";
import type { VerifiableCredential } from "@opencred/vc-core";
import { ValidationError } from "@opencred/shared";

/** Maximum bytes for a QR code (Version 40, Low EC). */
const MAX_QR_BYTES = 2953;

/**
 * Generate a QR code from a VerifiableCredential as a PNG data URL.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns A PNG data URL (base64-encoded).
 * @throws {ValidationError} if the credential JSON exceeds QR capacity.
 */
export async function generateQrPng(credential: VerifiableCredential): Promise<string> {
  const json = JSON.stringify(credential);
  const byteLength = Buffer.byteLength(json, "utf-8");

  if (byteLength > MAX_QR_BYTES) {
    throw new ValidationError(
      `Credential JSON (${byteLength} bytes) exceeds QR code capacity (${MAX_QR_BYTES} bytes). Consider using JSON export instead.`,
    );
  }

  return QRCode.toDataURL(json, {
    errorCorrectionLevel: "L",
    type: "image/png",
    margin: 2,
    width: 400,
  });
}

/**
 * Generate a QR code from a VerifiableCredential as an SVG string.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns An SVG string.
 * @throws {ValidationError} if the credential JSON exceeds QR capacity.
 */
export async function generateQrSvg(credential: VerifiableCredential): Promise<string> {
  const json = JSON.stringify(credential);
  const byteLength = Buffer.byteLength(json, "utf-8");

  if (byteLength > MAX_QR_BYTES) {
    throw new ValidationError(
      `Credential JSON (${byteLength} bytes) exceeds QR code capacity (${MAX_QR_BYTES} bytes). Consider using JSON export instead.`,
    );
  }

  return QRCode.toString(json, {
    errorCorrectionLevel: "L",
    type: "svg",
    margin: 2,
    width: 400,
  });
}

/**
 * Generate a QR code from a VerifiableCredential as a PNG Buffer.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns A PNG Buffer.
 * @throws {ValidationError} if the credential JSON exceeds QR capacity.
 */
export async function generateQrBuffer(credential: VerifiableCredential): Promise<Buffer> {
  const json = JSON.stringify(credential);
  const byteLength = Buffer.byteLength(json, "utf-8");

  if (byteLength > MAX_QR_BYTES) {
    throw new ValidationError(
      `Credential JSON (${byteLength} bytes) exceeds QR code capacity (${MAX_QR_BYTES} bytes). Consider using JSON export instead.`,
    );
  }

  return QRCode.toBuffer(json, {
    errorCorrectionLevel: "L",
    type: "png",
    margin: 2,
    width: 400,
  });
}
