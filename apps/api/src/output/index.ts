export { generateQrDataUrl, generateQrBuffer } from "./qr.js";
export type { QrOptions, QrSize } from "./qr.js";
export { generateCredentialPdf } from "./pdf.js";
export type { CredentialPdfInput } from "./pdf.js";

import { generateQrDataUrl, generateQrBuffer } from "./qr.js";
import { generateCredentialPdf } from "./pdf.js";
import { ValidationError } from "@opencred/shared";

// ---------------------------------------------------------------------------
// Convenience: package all output formats for a credential
// ---------------------------------------------------------------------------

export interface PackagedFormats {
  /** The credential itself in JSON-LD form */
  jsonld: Record<string, unknown>;
  /** QR code as a data:image/png;base64,… data-URL, or null if credential exceeds QR capacity */
  qr: string | null;
  /** PDF document as a base64-encoded string */
  pdf: string;
  /** Present when QR generation failed due to credential size (#137) */
  qrError?: string;
}

/**
 * Produce all three output formats for a packaged credential.
 *
 * If the credential is too large for a QR code the `qr` field will be
 * `null` and `qrError` will contain a sanitised error code, so the
 * remaining formats are still returned.
 */
export async function packageFormats(
  credential: Record<string, unknown>,
): Promise<PackagedFormats> {
  const credentialJson = JSON.stringify(credential);

  let qrDataUrl: string | null;
  let qrBuffer: Buffer | undefined;
  let qrError: string | undefined;

  try {
    qrBuffer = await generateQrBuffer(credentialJson);
    qrDataUrl = await generateQrDataUrl(credentialJson);
  } catch (err) {
    if (err instanceof ValidationError && err.message.includes("exceeds QR code capacity")) {
      qrDataUrl = null;
      qrError = "CREDENTIAL_TOO_LARGE_FOR_QR";
      qrBuffer = undefined;
    } else {
      throw err;
    }
  }

  const pdfBuffer = await generateCredentialPdf({ credential, qrBuffer });

  return {
    jsonld: credential,
    qr: qrDataUrl,
    pdf: pdfBuffer.toString("base64"),
    ...(qrError && { qrError }),
  };
}
