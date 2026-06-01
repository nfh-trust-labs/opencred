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
 * other consumer that calls `pixelpass.decode()` directly — expects. The
 * format-detection layer (`@opencred/shared`'s `detectCredentialInputFormat`)
 * identifies these payloads by attempting a decode rather than by sniffing
 * a magic prefix.
 *
 * Works completely offline — no network requests.
 */

import QRCode from "qrcode";
import type { VerifiableCredential } from "@opencred/vc-core";
import { ValidationError, encodePixelPass, decodePixelPass } from "@opencred/shared";
import type { CredentialInput } from "./types.js";

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
 * decode → JSON. Re-exported via the package surface for callers that
 * scan a QR and need the underlying JSON without a full verification.
 *
 * @param qrData - The raw string scanned from a QR code.
 * @returns The decompressed credential JSON string.
 * @throws If the data cannot be decoded.
 */
export function decodeQrData(qrData: string): string {
  return decodePixelPass(qrData);
}

/**
 * Resolve the QR payload for either a JSON-LD credential (PixelPass
 * compress) or a compact JWT/SD-JWT token (embed verbatim — already
 * compact, and verifiers expect the raw token).
 */
function resolveQrPayload(input: CredentialInput): string {
  switch (input.kind) {
    case "compact-token":
      return input.token;
    case "vc":
      return compressCredentialForQr(input.credential);
  }
}

/**
 * Build a precise capacity-exceeded error message for a QR generation
 * failure. The compressed-vs-verbatim distinction matters: telling a
 * caller their compact token was rejected "even after compression"
 * misleads them — no compression ran.
 */
function qrCapacityError(input: CredentialInput, err: unknown): string {
  const detail =
    input.kind === "compact-token"
      ? "Compact token exceeds QR data capacity."
      : "Credential too large for QR code even after compression.";
  const cause = err instanceof Error ? err.message : "unknown error";
  return `${detail} Consider using JSON export instead. (${cause})`;
}

/**
 * Generate a QR code from a credential as a PNG data URL.
 *
 * @returns A PNG data URL (base64-encoded).
 * @throws {ValidationError} if the data still exceeds QR capacity.
 */
export async function generateQrPng(input: CredentialInput): Promise<string> {
  const payload = resolveQrPayload(input);

  try {
    return await QRCode.toDataURL(payload, {
      errorCorrectionLevel: "L",
      type: "image/png",
      margin: 2,
      width: 400,
    });
  } catch (err) {
    throw new ValidationError(qrCapacityError(input, err));
  }
}

/**
 * Generate a QR code from a credential as an SVG string.
 *
 * @returns An SVG string.
 * @throws {ValidationError} if the data still exceeds QR capacity.
 */
export async function generateQrSvg(input: CredentialInput): Promise<string> {
  const payload = resolveQrPayload(input);

  try {
    return await QRCode.toString(payload, {
      errorCorrectionLevel: "L",
      type: "svg",
      margin: 2,
      width: 400,
    });
  } catch (err) {
    throw new ValidationError(qrCapacityError(input, err));
  }
}

/**
 * Generate a QR code from a credential as a PNG Buffer.
 *
 * @returns A PNG Buffer.
 * @throws {ValidationError} if the data still exceeds QR capacity.
 */
export async function generateQrBuffer(input: CredentialInput): Promise<Buffer> {
  const payload = resolveQrPayload(input);

  try {
    return await QRCode.toBuffer(payload, {
      errorCorrectionLevel: "L",
      type: "png",
      margin: 2,
      width: 400,
    });
  } catch (err) {
    throw new ValidationError(qrCapacityError(input, err));
  }
}
