import QRCode from "qrcode";
import { ValidationError } from "@opencred/shared";

// ---------------------------------------------------------------------------
// QR size presets — width in pixels
// ---------------------------------------------------------------------------

const SIZE_MAP: Record<QrSize, number> = {
  small: 200,
  medium: 400,
  large: 800,
};

export type QrSize = "small" | "medium" | "large";

export interface QrOptions {
  /** QR code pixel width (small=200, medium=400, large=800). Default: medium */
  size?: QrSize;
}

/**
 * Maximum bytes a Version-40 QR code can hold in binary mode.
 * We use a conservative limit so callers get a clear error before
 * qrcode silently truncates or throws an opaque internal error.
 */
const QR_BYTE_LIMIT = 2953;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a QR code as a `data:image/png;base64,…` data-URL string.
 */
export async function generateQrDataUrl(data: string, options?: QrOptions): Promise<string> {
  assertWithinLimit(data);

  const width = SIZE_MAP[options?.size ?? "medium"];

  return QRCode.toDataURL(data, {
    errorCorrectionLevel: "M",
    width,
    margin: 2,
  });
}

/**
 * Generate a QR code as a PNG `Buffer` (suitable for embedding in a PDF).
 */
export async function generateQrBuffer(data: string, options?: QrOptions): Promise<Buffer> {
  assertWithinLimit(data);

  const width = SIZE_MAP[options?.size ?? "medium"];

  return QRCode.toBuffer(data, {
    errorCorrectionLevel: "M",
    width,
    margin: 2,
  });
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

function assertWithinLimit(data: string): void {
  const byteLength = Buffer.byteLength(data, "utf-8");
  if (byteLength > QR_BYTE_LIMIT) {
    throw new ValidationError(
      `Credential data (${byteLength} bytes) exceeds QR code capacity (${QR_BYTE_LIMIT} bytes). ` +
        "Consider using a URL-based QR code instead.",
    );
  }
}
