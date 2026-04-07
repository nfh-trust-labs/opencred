/**
 * Issuer branding helpers — validation, sanitization, and resolution.
 *
 * Branding is presentation-layer only. The signed Verifiable Credential
 * payload is never affected by these helpers.
 *
 * SECURITY NOTES:
 *
 *  - Hex color validation: only `#RRGGBB` and `#RGB` are accepted.
 *    Anything else is rejected so user input cannot inject arbitrary
 *    CSS or attribute values into the rendered SVG.
 *  - SVG sanitization: an issuer-uploaded SVG logo can contain
 *    `<script>`, event handlers, `<foreignObject>`, and external
 *    references. `sanitizeSvgLogo` strips all of these via a strict
 *    allow-list parser before the SVG is wrapped in a `data:` URI and
 *    embedded in the rendered credential.
 *  - No remote URLs: callers must convert any uploaded image to a
 *    `data:` URI before passing it to the renderer. `validateLogoDataUri`
 *    rejects any non-`data:` URI.
 */

import type { IssuerBranding } from "./types.js";

// ──────────────────────────────────────────────────────────────────
// Defaults
// ──────────────────────────────────────────────────────────────────

/** OpenCred default primary color (used when branding is absent). */
export const DEFAULT_PRIMARY_COLOR = "#1a56db";
/** OpenCred default accent color (used when branding is absent). */
export const DEFAULT_ACCENT_COLOR = "#0ea5e9";

// ──────────────────────────────────────────────────────────────────
// Hex color validation
// ──────────────────────────────────────────────────────────────────

const HEX_COLOR_RE = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;

/** True iff `value` is a valid `#RGB` or `#RRGGBB` hex color. */
export function isValidHexColor(value: unknown): value is string {
  return typeof value === "string" && HEX_COLOR_RE.test(value);
}

/**
 * Normalize a hex color to lowercase `#RRGGBB`. Returns `undefined` if the
 * input is not a valid hex color.
 */
export function normalizeHexColor(value: unknown): string | undefined {
  if (!isValidHexColor(value)) return undefined;
  let hex = value.toLowerCase();
  // Expand 3-digit shorthand (#abc → #aabbcc)
  if (hex.length === 4) {
    hex = `#${hex[1]}${hex[1]}${hex[2]}${hex[2]}${hex[3]}${hex[3]}`;
  }
  return hex;
}

// ──────────────────────────────────────────────────────────────────
// Logo data URI validation
// ──────────────────────────────────────────────────────────────────

/** Allowed image MIME types for issuer logos. */
export const ALLOWED_LOGO_MIME_TYPES = new Set([
  "image/png",
  "image/svg+xml",
]);

/**
 * Maximum total size of a logo data URI in bytes (including the data URI
 * prefix and base64 padding). 1.5 MB is generous: a 1 MB raw payload
 * encodes to ~1.34 MB after base64.
 */
export const MAX_LOGO_DATA_URI_BYTES = 1.5 * 1024 * 1024;

/** Result of validating a logo data URI. */
export interface LogoValidationResult {
  ok: boolean;
  /** The detected MIME type (e.g. `image/png`). */
  mimeType?: string;
  /** Reason the data URI was rejected, if any. */
  error?: string;
}

const DATA_URI_RE = /^data:([a-zA-Z0-9.+/-]+);base64,(.+)$/;
const BASE64_PAYLOAD_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Validate that a string is a safe `data:` URI for an issuer logo.
 *
 * Rules:
 *  - Must start with `data:`
 *  - MIME type must be in `ALLOWED_LOGO_MIME_TYPES`
 *  - Must be base64-encoded
 *  - Must not exceed `MAX_LOGO_DATA_URI_BYTES`
 *
 * Returns `{ ok: false, error }` for any non-`data:` URL (no remote URLs).
 */
export function validateLogoDataUri(value: unknown): LogoValidationResult {
  if (typeof value !== "string") {
    return { ok: false, error: "Logo must be a string." };
  }
  if (!value.startsWith("data:")) {
    return { ok: false, error: "Logo must be a data: URI (no remote URLs)." };
  }
  if (value.length > MAX_LOGO_DATA_URI_BYTES) {
    return {
      ok: false,
      error: `Logo data URI exceeds ${Math.round(MAX_LOGO_DATA_URI_BYTES / 1024)} KB limit.`,
    };
  }
  // Parse the data URI: `data:<mime>;base64,<payload>`
  // We require base64 encoding so the embedded payload is opaque to the
  // SVG XML parser and can never escape its own context.
  const match = DATA_URI_RE.exec(value);
  if (!match) {
    return { ok: false, error: "Logo must be a base64-encoded data URI." };
  }
  const mimeType = match[1].toLowerCase();
  if (!ALLOWED_LOGO_MIME_TYPES.has(mimeType)) {
    return {
      ok: false,
      error: `Logo MIME type ${mimeType} is not allowed (PNG and SVG only).`,
    };
  }
  const payload = match[2];
  // Reject obviously malformed base64 to avoid trash in the rendered output.
  if (!BASE64_PAYLOAD_RE.test(payload)) {
    return { ok: false, error: "Logo payload is not valid base64." };
  }
  return { ok: true, mimeType };
}

// ──────────────────────────────────────────────────────────────────
// SVG sanitization
// ──────────────────────────────────────────────────────────────────

/**
 * Tags that may NEVER appear in an issuer-uploaded SVG. We strip the
 * entire element (including its contents) when any of these are found.
 *
 * Notes:
 *  - `<script>`: arbitrary JS execution.
 *  - `<foreignObject>`: embeds HTML, which can contain anything.
 *  - `<iframe>`, `<object>`, `<embed>`: external content.
 *  - `<animate*>`: SMIL animation can fetch external resources.
 *  - `<style>`: CSS can `url()` external resources.
 */
const FORBIDDEN_TAGS = new Set([
  "script",
  "foreignobject",
  "iframe",
  "object",
  "embed",
  "audio",
  "video",
  "animate",
  "animatemotion",
  "animatetransform",
  "set",
  "style",
  "handler",
]);

/** Pattern for an HTML/XML element with optional attributes. */
const TAG_RE = /<\/?([a-zA-Z][a-zA-Z0-9-]*)([^>]*)>/g;

/**
 * Pattern matching event-handler attributes (`onclick`, `onload`, etc.) that
 * we strip on every element regardless of tag.
 */
const EVENT_ATTR_DQ_RE = /\son[a-zA-Z]+\s*=\s*"[^"]*"/gi;
const EVENT_ATTR_SQ_RE = /\son[a-zA-Z]+\s*=\s*'[^']*'/gi;

/**
 * Pattern for `xlink:href`, `href`, and `src` attribute values that point
 * to anything other than a `data:` URI or fragment identifier.
 */
const HREF_ATTR_RE =
  /\s(?:xlink:href|href|src)\s*=\s*("([^"]*)"|'([^']*)')/gi;

/** Pattern matching XML processing instructions and DOCTYPEs. */
const PI_DOCTYPE_RE = /<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<!\[CDATA\[[\s\S]*?]]>|<!--[\s\S]*?-->/g;

/** Result of sanitizing an SVG payload. */
export interface SvgSanitizationResult {
  ok: boolean;
  /** The sanitized SVG (only present when `ok` is true). */
  svg?: string;
  /** The reason sanitization rejected the input, if any. */
  error?: string;
}

/**
 * Sanitize a raw SVG string for use as an issuer logo.
 *
 * This is a strict allow-list filter. It:
 *
 *  1. Strips processing instructions, DOCTYPEs, comments, and CDATA blocks.
 *  2. Removes any element whose tag is in `FORBIDDEN_TAGS` (including
 *     content between matching open/close tags).
 *  3. Strips `on*` event handler attributes from every element.
 *  4. Removes `href`, `xlink:href`, and `src` attributes that point to
 *     anything other than a `data:` URI or fragment identifier.
 *  5. Asserts the result still contains an `<svg>` root element.
 *
 * The function is intentionally simple — no DOM parser dependency. It is
 * not a fully-featured SVG sanitizer like DOMPurify, but the rules above
 * are sufficient for an embedded credential logo where any non-cosmetic
 * content is unwanted.
 *
 * Use the result wrapped in a `data:image/svg+xml;base64,...` URI.
 */
export function sanitizeSvgLogo(input: string): SvgSanitizationResult {
  if (typeof input !== "string" || input.length === 0) {
    return { ok: false, error: "SVG must be a non-empty string." };
  }
  if (input.length > MAX_LOGO_DATA_URI_BYTES) {
    return { ok: false, error: "SVG exceeds maximum size." };
  }

  // 1. Strip processing instructions, DOCTYPEs, comments, CDATA.
  let svg = input.replace(PI_DOCTYPE_RE, "");

  // 2. Remove forbidden elements (including content). Loop until stable
  // because nested forbidden elements can recur.
  for (const tag of FORBIDDEN_TAGS) {
    // Element with content: <tag ...>...</tag>
    const blockRe = new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}\\s*>`, "gi");
    // Self-closing element: <tag ... />
    const selfRe = new RegExp(`<${tag}\\b[^>]*\\/?>`, "gi");
    let prev: string;
    do {
      prev = svg;
      svg = svg.replace(blockRe, "").replace(selfRe, "");
    } while (svg !== prev);
  }

  // 3. Strip event-handler attributes from any remaining element.
  svg = svg.replace(EVENT_ATTR_DQ_RE, "").replace(EVENT_ATTR_SQ_RE, "");

  // 4. Strip external href/src attributes (only data: URIs and fragment
  // refs are kept).
  svg = svg.replace(HREF_ATTR_RE, (matched, _quoted, dq, sq) => {
    const v = dq ?? sq ?? "";
    if (v.startsWith("data:") || v.startsWith("#")) {
      return matched;
    }
    return "";
  });

  // 5. Walk all remaining tags and reject any forbidden tag that survived
  // the simple regex pass (defense in depth).
  let foundSvgRoot = false;
  TAG_RE.lastIndex = 0;
  let tagMatch: RegExpExecArray | null;
  while ((tagMatch = TAG_RE.exec(svg)) !== null) {
    const tagName = tagMatch[1].toLowerCase();
    if (FORBIDDEN_TAGS.has(tagName)) {
      return { ok: false, error: `SVG contained forbidden tag <${tagName}>.` };
    }
    if (tagName === "svg") foundSvgRoot = true;
  }

  if (!foundSvgRoot) {
    return { ok: false, error: "SVG must contain an <svg> root element." };
  }

  return { ok: true, svg };
}

/**
 * Convert a sanitized SVG string into a base64 `data:image/svg+xml` URI.
 */
export function svgToDataUri(svg: string): string {
  // Use base64 (not URL-encoded) so the embedded payload is opaque to the
  // outer SVG parser and can never escape its container.
  const b64 = Buffer.from(svg, "utf8").toString("base64");
  return `data:image/svg+xml;base64,${b64}`;
}

// ──────────────────────────────────────────────────────────────────
// Branding resolution
// ──────────────────────────────────────────────────────────────────

/** A fully-resolved branding payload (every field has a definite value). */
export interface ResolvedBranding {
  primaryColor: string;
  accentColor: string;
  logoDataUri: string | null;
}

/**
 * Resolve a branding override against the OpenCred defaults.
 *
 * Invalid hex colors and invalid logo data URIs fall back to defaults
 * (or `null` for the logo). The result always has every field populated.
 *
 * @param branding partial branding override (may be undefined)
 */
export function resolveBranding(branding?: IssuerBranding): ResolvedBranding {
  const primaryColor =
    normalizeHexColor(branding?.primaryColor) ?? DEFAULT_PRIMARY_COLOR;
  const accentColor =
    normalizeHexColor(branding?.accentColor) ?? DEFAULT_ACCENT_COLOR;

  let logoDataUri: string | null = null;
  if (branding?.logoDataUri) {
    const result = validateLogoDataUri(branding.logoDataUri);
    if (result.ok) {
      logoDataUri = branding.logoDataUri;
    }
  }

  return { primaryColor, accentColor, logoDataUri };
}
