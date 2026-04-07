/**
 * Issuer branding — main-process validation, sanitization, and persistence.
 *
 * The renderer can submit:
 *   - A logo file (raw PNG bytes or raw SVG markup, base64-encoded over IPC)
 *   - A primary hex color
 *   - An accent hex color
 *
 * This module is the single point of validation. Logos are size-checked,
 * MIME-checked, and sanitized (SVGs) before being converted to a base64
 * `data:` URI and persisted in electron-store.
 *
 * SECURITY NOTES:
 *
 *  - **No remote URLs**: an issuer never supplies a URL — only file bytes.
 *    The persisted form is always a `data:` URI.
 *  - **Image whitelist**: only `image/png` and `image/svg+xml` are accepted.
 *  - **PNG metadata stripping**: ancillary chunks (`tEXt`, `iTXt`, `zTXt`,
 *    `eXIf`, `tIME`, `pHYs`, etc.) are removed before persistence so the
 *    rendered credential never carries any of the issuer's photo metadata.
 *  - **SVG sanitization**: handled by `@opencred/templates` which strips
 *    `<script>`, `<foreignObject>`, event handlers, and external refs.
 *  - **Size cap**: 1 MB raw payload (a generous cap; the data URI overhead
 *    pushes the persisted size to ~1.34 MB).
 *  - **Dimension cap**: PNGs over 1024×1024 are rejected at validation
 *    time. SVGs are not rasterized; the cap is enforced via byte size.
 */

import {
  isValidHexColor,
  normalizeHexColor,
  sanitizeSvgLogo,
  svgToDataUri,
  validateLogoDataUri,
  type IssuerBranding,
} from "@opencred/templates";
import { getStore, type IssuerBrandingStoreEntry } from "./store.js";
import type {
  BrandingGetResponse,
  BrandingSetRequest,
  BrandingSetResponse,
  IssuerBrandingPayload,
} from "../shared/ipc-types.js";

// ──────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────

/** Maximum raw logo bytes accepted (1 MB). */
export const MAX_LOGO_RAW_BYTES = 1024 * 1024;

/** Maximum logo dimensions (PNG only — SVG is byte-capped). */
export const MAX_LOGO_DIMENSION = 1024;

/** MIME types we accept on the IPC boundary. */
const ALLOWED_MIME_TYPES = new Set(["image/png", "image/svg+xml"]);

// ──────────────────────────────────────────────────────────────────
// PNG validation and metadata stripping
// ──────────────────────────────────────────────────────────────────

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/**
 * Critical chunks that we always retain. Everything else is treated as
 * an ancillary chunk and dropped — that is sufficient to remove EXIF,
 * XMP, text, timestamp, and physical-pixel chunks.
 */
const CRITICAL_PNG_CHUNKS = new Set(["IHDR", "PLTE", "IDAT", "IEND"]);

interface PngParseResult {
  ok: true;
  width: number;
  height: number;
  /** PNG bytes with all ancillary chunks removed. */
  stripped: Buffer;
}

interface PngParseError {
  ok: false;
  error: string;
}

/**
 * Parse a PNG buffer, validate dimensions, and return a copy with all
 * ancillary (metadata) chunks stripped.
 *
 * Returns `{ ok: false, error }` if the buffer is not a valid PNG.
 */
function parseAndStripPng(buf: Buffer): PngParseResult | PngParseError {
  if (buf.length < PNG_SIGNATURE.length + 12) {
    return { ok: false, error: "PNG payload too short." };
  }
  if (!buf.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
    return { ok: false, error: "PNG signature missing." };
  }

  // The IHDR chunk must immediately follow the signature.
  // Layout: 4-byte length | 4-byte type | data | 4-byte CRC
  let cursor = PNG_SIGNATURE.length;
  const ihdrLength = buf.readUInt32BE(cursor);
  cursor += 4;
  const ihdrType = buf.subarray(cursor, cursor + 4).toString("ascii");
  cursor += 4;
  if (ihdrType !== "IHDR" || ihdrLength !== 13) {
    return { ok: false, error: "PNG IHDR chunk is malformed." };
  }
  const width = buf.readUInt32BE(cursor);
  const height = buf.readUInt32BE(cursor + 4);
  cursor += ihdrLength + 4; // skip data + CRC

  if (width === 0 || height === 0) {
    return { ok: false, error: "PNG dimensions are invalid." };
  }
  if (width > MAX_LOGO_DIMENSION || height > MAX_LOGO_DIMENSION) {
    return {
      ok: false,
      error: `PNG dimensions ${width}x${height} exceed ${MAX_LOGO_DIMENSION}x${MAX_LOGO_DIMENSION}.`,
    };
  }

  // Walk all chunks, dropping ancillary ones.
  const keepChunks: Buffer[] = [PNG_SIGNATURE];
  // Re-emit IHDR at the start (always required, never ancillary).
  keepChunks.push(buf.subarray(PNG_SIGNATURE.length, cursor));

  while (cursor + 12 <= buf.length) {
    const length = buf.readUInt32BE(cursor);
    const type = buf.subarray(cursor + 4, cursor + 8).toString("ascii");
    const total = 12 + length; // length + type + data + crc

    if (cursor + total > buf.length) {
      return { ok: false, error: "PNG chunk extends past end of file." };
    }

    if (CRITICAL_PNG_CHUNKS.has(type)) {
      keepChunks.push(buf.subarray(cursor, cursor + total));
    }
    // Ancillary chunks are silently dropped — this includes:
    // tEXt, iTXt, zTXt, eXIf, tIME, pHYs, sRGB, gAMA, cHRM, bKGD, etc.

    cursor += total;
    if (type === "IEND") {
      break;
    }
  }

  // Sanity check: must contain at least one IDAT and an IEND.
  const stripped = Buffer.concat(keepChunks);
  if (!stripped.includes("IDAT") || !stripped.includes("IEND")) {
    return { ok: false, error: "PNG missing required IDAT/IEND chunks." };
  }

  return { ok: true, width, height, stripped };
}

// ──────────────────────────────────────────────────────────────────
// Logo processing
// ──────────────────────────────────────────────────────────────────

interface LogoProcessResult {
  ok: boolean;
  /** Sanitized base64 `data:` URI ready for persistence. */
  dataUri?: string;
  mimeType?: "image/png" | "image/svg+xml";
  error?: string;
}

/**
 * Validate a raw logo file from the renderer and convert it to a sanitized
 * `data:` URI suitable for persistence and embedding in SVG output.
 *
 * Steps:
 *   1. Decode the base64 input bytes.
 *   2. Enforce the byte cap (1 MB).
 *   3. For PNG: parse, validate dimensions, strip ancillary chunks.
 *   4. For SVG: sanitize (strip script, foreignObject, event handlers,
 *      external refs) via `@opencred/templates`.
 *   5. Re-encode the sanitized bytes as a base64 `data:` URI.
 */
export function processLogoFile(file: NonNullable<BrandingSetRequest["logoFile"]>): LogoProcessResult {
  const mimeType = file.mimeType?.toLowerCase();
  if (typeof mimeType !== "string" || !ALLOWED_MIME_TYPES.has(mimeType)) {
    return {
      ok: false,
      error: `Logo MIME type ${file.mimeType ?? "(missing)"} is not allowed (PNG and SVG only).`,
    };
  }

  let raw: Buffer;
  try {
    raw = Buffer.from(file.base64, "base64");
  } catch {
    return { ok: false, error: "Logo bytes are not valid base64." };
  }

  if (raw.length === 0) {
    return { ok: false, error: "Logo file is empty." };
  }
  if (raw.length > MAX_LOGO_RAW_BYTES) {
    return {
      ok: false,
      error: `Logo exceeds ${Math.round(MAX_LOGO_RAW_BYTES / 1024)} KB limit.`,
    };
  }

  if (mimeType === "image/png") {
    const parsed = parseAndStripPng(raw);
    if (!parsed.ok) {
      return { ok: false, error: parsed.error };
    }
    const dataUri = `data:image/png;base64,${parsed.stripped.toString("base64")}`;
    // Final defense-in-depth check via the templates validator.
    const validation = validateLogoDataUri(dataUri);
    if (!validation.ok) {
      return { ok: false, error: validation.error ?? "Logo failed validation." };
    }
    return { ok: true, mimeType: "image/png", dataUri };
  }

  // image/svg+xml — sanitize
  const svgText = raw.toString("utf8");
  const sanitization = sanitizeSvgLogo(svgText);
  if (!sanitization.ok || !sanitization.svg) {
    return { ok: false, error: sanitization.error ?? "SVG sanitization failed." };
  }
  const dataUri = svgToDataUri(sanitization.svg);
  const validation = validateLogoDataUri(dataUri);
  if (!validation.ok) {
    return { ok: false, error: validation.error ?? "Logo failed validation." };
  }
  return { ok: true, mimeType: "image/svg+xml", dataUri };
}

// ──────────────────────────────────────────────────────────────────
// Persistence helpers
// ──────────────────────────────────────────────────────────────────

/**
 * Read the persisted issuer branding entry. Used by both the IPC handler
 * and the SVG renderer to apply branding when packaging credentials.
 */
export function readBrandingFromStore(): IssuerBrandingStoreEntry | undefined {
  try {
    const store = getStore();
    return store.get("issuerBranding") as IssuerBrandingStoreEntry | undefined;
  } catch {
    return undefined;
  }
}

/**
 * Convert the persisted store entry into the renderer-facing
 * `IssuerBranding` payload (drops the mime type and timestamp).
 *
 * Returns `undefined` if no branding has been configured.
 */
export function getActiveBranding(): IssuerBranding | undefined {
  const entry = readBrandingFromStore();
  if (!entry) return undefined;
  if (!entry.logoDataUri && !entry.primaryColor && !entry.accentColor) {
    return undefined;
  }
  const branding: IssuerBranding = {};
  if (entry.logoDataUri) branding.logoDataUri = entry.logoDataUri;
  if (entry.primaryColor) branding.primaryColor = entry.primaryColor;
  if (entry.accentColor) branding.accentColor = entry.accentColor;
  return branding;
}

/**
 * Convert the persisted store entry into the IPC response payload.
 */
function toResponsePayload(entry: IssuerBrandingStoreEntry | undefined): BrandingGetResponse {
  if (!entry || (!entry.logoDataUri && !entry.primaryColor && !entry.accentColor)) {
    return { configured: false };
  }
  const branding: IssuerBrandingPayload = {};
  if (entry.logoDataUri) branding.logoDataUri = entry.logoDataUri;
  if (entry.primaryColor) branding.primaryColor = entry.primaryColor;
  if (entry.accentColor) branding.accentColor = entry.accentColor;
  return {
    configured: true,
    branding,
    updatedAt: entry.updatedAt,
  };
}

// ──────────────────────────────────────────────────────────────────
// IPC handlers
// ──────────────────────────────────────────────────────────────────

/** BRANDING_GET — read the persisted issuer branding. */
export function handleBrandingGet(): BrandingGetResponse {
  return toResponsePayload(readBrandingFromStore());
}

/**
 * BRANDING_SET — persist new branding values.
 *
 * Validates colors and (if a logo is provided) decodes, sanitizes, and
 * re-encodes the logo. Partial updates are supported: omitted fields keep
 * their previous value. Setting `removeLogo: true` clears the logo while
 * keeping the colors.
 */
export function handleBrandingSet(request: BrandingSetRequest): BrandingSetResponse {
  // Validate colors.
  let primaryColor: string | undefined;
  if (request.primaryColor !== undefined) {
    if (!isValidHexColor(request.primaryColor)) {
      return {
        success: false,
        error: "Primary color must be a hex value in the form #RRGGBB.",
        errorField: "primaryColor",
      };
    }
    primaryColor = normalizeHexColor(request.primaryColor);
  }

  let accentColor: string | undefined;
  if (request.accentColor !== undefined) {
    if (!isValidHexColor(request.accentColor)) {
      return {
        success: false,
        error: "Accent color must be a hex value in the form #RRGGBB.",
        errorField: "accentColor",
      };
    }
    accentColor = normalizeHexColor(request.accentColor);
  }

  // Process the logo (if provided).
  let logoDataUri: string | undefined;
  let logoMimeType: "image/png" | "image/svg+xml" | undefined;
  let removeLogo = false;
  if (request.logoFile) {
    const result = processLogoFile(request.logoFile);
    if (!result.ok || !result.dataUri || !result.mimeType) {
      return {
        success: false,
        error: result.error ?? "Logo could not be processed.",
        errorField: "logo",
      };
    }
    logoDataUri = result.dataUri;
    logoMimeType = result.mimeType;
  } else if (request.removeLogo) {
    removeLogo = true;
  }

  // Merge with the existing entry.
  const previous = readBrandingFromStore() ?? {};
  const next: IssuerBrandingStoreEntry = {
    primaryColor: primaryColor ?? previous.primaryColor,
    accentColor: accentColor ?? previous.accentColor,
    logoDataUri: logoDataUri ?? (removeLogo ? undefined : previous.logoDataUri),
    logoMimeType: logoMimeType ?? (removeLogo ? undefined : previous.logoMimeType),
    updatedAt: new Date().toISOString(),
  };

  // Strip undefined keys for a clean store entry.
  const cleaned: IssuerBrandingStoreEntry = { updatedAt: next.updatedAt };
  if (next.primaryColor) cleaned.primaryColor = next.primaryColor;
  if (next.accentColor) cleaned.accentColor = next.accentColor;
  if (next.logoDataUri) cleaned.logoDataUri = next.logoDataUri;
  if (next.logoMimeType) cleaned.logoMimeType = next.logoMimeType;

  try {
    const store = getStore();
    store.set("issuerBranding", cleaned);
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : "Failed to persist branding.",
    };
  }

  const branding: IssuerBrandingPayload = {};
  if (cleaned.primaryColor) branding.primaryColor = cleaned.primaryColor;
  if (cleaned.accentColor) branding.accentColor = cleaned.accentColor;
  if (cleaned.logoDataUri) branding.logoDataUri = cleaned.logoDataUri;

  return {
    success: true,
    branding,
    updatedAt: cleaned.updatedAt,
  };
}

/** BRANDING_CLEAR — remove all persisted branding. */
export function handleBrandingClear(): { success: boolean; error?: string } {
  try {
    const store = getStore();
    // electron-store typings expect `delete(key)`, which removes the entry.
    (store as unknown as { delete: (key: string) => void }).delete("issuerBranding");
    return { success: true };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : "Failed to clear branding.",
    };
  }
}
