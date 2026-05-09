/**
 * PixelPass codec for OpenCred QR / PDF-embedded credentials.
 *
 * OpenCred compresses credentials before embedding them in QR codes and PDF
 * metadata so they fit in QR capacity and stay small in metadata streams.
 * The compression pipeline is:
 *
 *   JSON → CBOR encode → zlib compress (level 9) → Base45 encode
 *
 * Encoded payloads carry the `OPENCRED1:` header so a decoder can
 * positively identify the format. This module exposes only the decode
 * direction — issuance code calls the encode side directly via
 * `@mosip/pixelpass` (see `apps/server/src/packaging/qr-generator.ts` and
 * the equivalent desktop module). Verification only ever decodes, so we
 * keep the surface narrow here.
 */

import { createRequire } from "node:module";

// PixelPass is a CommonJS module — go through createRequire for ESM compat.
const require = createRequire(import.meta.url);
const pixelpass = require("@mosip/pixelpass") as {
  decode: (data: string) => string;
};

/** Header prefix that identifies an OpenCred-formatted PixelPass payload. */
export const OPENCRED_PIXELPASS_HEADER = "OPENCRED1:";

/**
 * Decode a PixelPass-compressed OpenCred payload back to credential JSON.
 *
 * Strips the `OPENCRED1:` header if present, then runs the inverse pipeline
 * (Base45 → zlib decompress → CBOR decode) to recover the original JSON
 * string. Caller is responsible for parsing the JSON.
 *
 * @param data - Either an `OPENCRED1:`-prefixed string or the raw Base45
 *               body of one. Non-prefixed input is accepted to keep this
 *               tolerant of upstream stripping.
 * @returns The decoded credential JSON string.
 * @throws If the payload cannot be decoded.
 */
export function decodePixelPass(data: string): string {
  const body = data.startsWith(OPENCRED_PIXELPASS_HEADER)
    ? data.slice(OPENCRED_PIXELPASS_HEADER.length)
    : data;
  return pixelpass.decode(body);
}
