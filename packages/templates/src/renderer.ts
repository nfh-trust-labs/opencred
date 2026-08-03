/**
 * SVG template renderer.
 *
 * Substitutes {{placeholder}} tokens in SVG templates with actual values.
 * Supports nested subject fields ({{subject.fieldName}}) and
 * conditional sections ({{#field}}...{{/field}}).
 */

import type { RenderOptions } from "./types.js";

const PLACEHOLDER_RE = /\{\{([^#/}]+?)\}\}/g;
const CONDITIONAL_RE = /\{\{#(\w+)\}\}([\s\S]*?)\{\{\/\1\}\}/g;

const DEFAULT_PRIMARY_COLOR = "#1a56db";

// Color values land inside the template's <style> block, where XML escaping
// offers no protection — a `}` breaks out of the rule and arbitrary CSS (or a
// closed </style> followed by markup) follows. Only allow shapes that cannot
// contain `;{}<>&"'` or url(): hex, bare color names, and rgb()/hsl()
// functions restricted to numeric arguments.
const SAFE_COLOR_RE =
  /^(?:#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})|[a-zA-Z]+|(?:rgb|rgba|hsl|hsla)\([0-9.,%\s/]*\))$/;

// Image values land in <image href="...">. Only raster data URIs are allowed:
// image/svg+xml is deliberately excluded (nested SVG can carry <script>), as
// is every non-data scheme (javascript:, http:, file:). The base64 charset
// restriction also rules out quote/angle-bracket attribute breakouts.
const SAFE_IMAGE_DATA_URI_RE =
  /^data:image\/(?:png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/;

/** Return the color if it matches the safe shape, else the fallback. */
function sanitizeColor(value: string | undefined, fallback: string): string {
  return value !== undefined && SAFE_COLOR_RE.test(value) ? value : fallback;
}

/** True if the value is a raster-image data URI safe for href interpolation. */
function isSafeImageDataUri(value: string): boolean {
  return SAFE_IMAGE_DATA_URI_RE.test(value);
}

/** Return the dimension as a digit string, else the fallback. */
function sanitizeDimension(value: number | undefined, fallback: number): string {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? String(Math.round(value))
    : String(fallback);
}

/**
 * Render an SVG template with the given values and customization.
 */
export function renderSvg(svgTemplate: string, options: RenderOptions): string {
  const { values, customization } = options;

  // Build a flat lookup map for placeholders
  const lookup = new Map<string, string>();

  // issuerName and credentialTitle derive from attacker-controlled credential
  // fields (issuer.name, type[]) — escape like every other credential value.
  lookup.set("issuerName", escapeXml(values.issuerName));
  lookup.set("credentialTitle", escapeXml(values.credentialTitle));
  // formatDate falls back to the raw input for unparseable dates, so its
  // output is credential-derived too.
  lookup.set("validFrom", escapeXml(formatDate(values.validFrom)));
  lookup.set(
    "validUntil",
    values.validUntil ? escapeXml(formatDate(values.validUntil)) : "No expiry",
  );

  // Subject fields
  for (const [key, val] of Object.entries(values.subject)) {
    lookup.set(`subject.${key}`, escapeXml(val));
  }

  // QR code — href context; drop anything that isn't a raster data URI
  if (values.qrCode && isSafeImageDataUri(values.qrCode)) {
    lookup.set("qrCode", values.qrCode);
  }

  // Customization defaults. Colors are interpolated into a <style> block, so
  // they are allowlisted (not merely escaped) and fall back on mismatch.
  lookup.set("primaryColor", sanitizeColor(customization?.primaryColor, DEFAULT_PRIMARY_COLOR));
  lookup.set("backgroundColor", sanitizeColor(customization?.backgroundColor, "#ffffff"));
  lookup.set("secondaryColor", sanitizeColor(customization?.secondaryColor, "#2d5986"));
  lookup.set("textColor", sanitizeColor(customization?.textColor, "#333333"));
  lookup.set("labelColor", sanitizeColor(customization?.labelColor, "#666666"));
  lookup.set("logoWidth", sanitizeDimension(customization?.logoWidth, 50));
  lookup.set("logoHeight", sanitizeDimension(customization?.logoHeight, 50));
  // Default footer is intentionally a generic verification disclaimer
  // — no "powered by" attribution. The PDF generator follows the same
  // convention. To suppress the footer entirely, pass `footerText: ""`.
  lookup.set(
    "footerText",
    escapeXml(
      customization?.footerText ??
        "This credential is digitally signed and can be independently verified.",
    ),
  );

  if (customization?.logoDataUri && isSafeImageDataUri(customization.logoDataUri)) {
    lookup.set("logoDataUri", customization.logoDataUri);
  }

  if (customization?.sealDataUri && isSafeImageDataUri(customization.sealDataUri)) {
    lookup.set("sealDataUri", customization.sealDataUri);
  }

  if (customization?.issuerDisplayName) {
    lookup.set("issuerName", escapeXml(customization.issuerDisplayName));
  }

  // Process conditionals first ({{#field}}...{{/field}})
  let result = svgTemplate.replace(CONDITIONAL_RE, (_match, field: string, content: string) => {
    const value = lookup.get(field);
    return value ? content : "";
  });

  // Then substitute placeholders
  result = result.replace(PLACEHOLDER_RE, (_match, key: string) => {
    const trimmedKey = key.trim();
    return lookup.get(trimmedKey) ?? "";
  });

  return result;
}

/** Format ISO date to human-readable. */
function formatDate(iso: string): string {
  try {
    const date = new Date(iso);
    if (isNaN(date.getTime())) return iso;
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

/** Escape XML special characters. */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}
