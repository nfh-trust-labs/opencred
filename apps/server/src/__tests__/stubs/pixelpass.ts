/**
 * Stub for `@mosip/pixelpass` used by the server test suite.
 *
 * `detectCredentialInputFormat` (in `@opencred/shared`) classifies bare
 * PixelPass payloads by attempting a decode — a successful decode is the
 * positive identification. The stub must therefore:
 *
 *   1. Round-trip data through `generateQRData` → `decode` so encode/decode
 *      tests still pass.
 *   2. Throw on inputs that were not produced by this stub's
 *      `generateQRData`, so the format detector does not false-positive
 *      arbitrary strings as PixelPass.
 *
 * The on-the-wire shape is irrelevant; only consumers care about the
 * round-trip and the throw-on-invalid contract.
 */

const STUB_MARKER = "PPSTUB:";

export function generateQRData(data: string, _header?: string): string {
  return STUB_MARKER + Buffer.from(data, "utf8").toString("hex").toUpperCase();
}

export function decode(data: string): string {
  if (!data.startsWith(STUB_MARKER)) {
    throw new Error("Invalid PixelPass payload (stub): missing marker");
  }
  return Buffer.from(data.slice(STUB_MARKER.length), "hex").toString("utf8");
}
