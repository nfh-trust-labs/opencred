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
  /** QR code as a data:image/png;base64,… data-URL */
  qr: string;
  /** PDF document as a base64-encoded string */
  pdf: string;
}

/**
 * Produce all three output formats for a packaged credential.
 *
 * If the credential is too large for a QR code the `qr` field will
 * contain a descriptive error message prefixed with `error:` rather
 * than throwing, so the remaining formats are still returned.
 */
export async function packageFormats(
  credential: Record<string, unknown>,
): Promise<PackagedFormats> {
  const credentialJson = JSON.stringify(credential);

  let qrDataUrl: string;
  let qrBuffer: Buffer | undefined;

  try {
    qrBuffer = await generateQrBuffer(credentialJson);
    qrDataUrl = await generateQrDataUrl(credentialJson);
  } catch (err) {
    if (err instanceof ValidationError && err.message.includes("exceeds QR code capacity")) {
      // Credential is too large — degrade gracefully
      qrDataUrl = `error: ${err.message}`;
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
  };
}
