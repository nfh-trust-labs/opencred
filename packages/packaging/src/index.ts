/**
 * @opencred/packaging — shared offline credential packaging primitives.
 *
 * The PDF certificate generator and QR encoder used by BOTH the desktop
 * app and the headless Docker server, so the issued credential looks
 * identical across surfaces. Format/zip orchestration (which formats to
 * emit, JSON export, compact-token decoding) stays in each app's
 * `packager.ts`; this package owns the rendering + QR encoding core.
 */

export { generatePdf, PDF_CREDENTIAL_INFO_KEY } from "./pdf-generator.js";
export type { PdfOptions } from "./pdf-generator.js";

export {
  compressCredentialForQr,
  decodeQrData,
  generateQrPng,
  generateQrSvg,
  generateQrBuffer,
} from "./qr-generator.js";

export type { CredentialInput, PartialVerifiableCredential, PackagingLogger } from "./types.js";
