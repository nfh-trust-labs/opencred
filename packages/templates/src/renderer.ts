/**
 * SVG template renderer.
 *
 * Substitutes {{placeholder}} tokens in SVG templates with actual values.
 * Supports nested subject fields ({{subject.fieldName}}) and
 * conditional sections ({{#field}}...{{/field}}).
 *
 * Issuer branding (logo + primary/accent colors) is resolved via the
 * `resolveBranding` helper. When branding fields are absent or invalid the
 * renderer falls back to OpenCred defaults — the rendered credential never
 * fails because of a bad branding configuration.
 */

import type { IssuerBranding, RenderOptions, TemplateCustomization } from "./types.js";
import {
  DEFAULT_ACCENT_COLOR,
  DEFAULT_PRIMARY_COLOR,
  resolveBranding,
} from "./branding.js";

const PLACEHOLDER_RE = /\{\{([^#/}]+?)\}\}/g;
const CONDITIONAL_RE = /\{\{#(\w+)\}\}([\s\S]*?)\{\{\/\1\}\}/g;

/**
 * Render an SVG template with the given values and customization.
 *
 * Branding precedence (highest to lowest):
 *   1. `customization.primaryColor`, `customization.accentColor`,
 *      `customization.logoDataUri` — explicit per-render overrides.
 *   2. `customization.branding` — issuer-managed default branding.
 *   3. OpenCred defaults — applied when nothing else is set.
 */
export function renderSvg(svgTemplate: string, options: RenderOptions): string {
  const { values, customization } = options;

  // Resolve branding overrides into a flat, validated payload.
  const merged = mergeCustomization(customization);
  const branding = resolveBranding(merged);

  // Build a flat lookup map for placeholders
  const lookup = new Map<string, string>();

  lookup.set("issuerName", values.issuerName);
  lookup.set("credentialTitle", values.credentialTitle);
  lookup.set("validFrom", formatDate(values.validFrom));
  lookup.set("validUntil", values.validUntil ? formatDate(values.validUntil) : "No expiry");

  // Subject fields
  for (const [key, val] of Object.entries(values.subject)) {
    lookup.set(`subject.${key}`, escapeXml(val));
  }

  // QR code
  if (values.qrCode) {
    lookup.set("qrCode", values.qrCode);
  }

  // Branding placeholders. Hex colors are validated by `resolveBranding`,
  // so they are safe to insert as-is — but we still XML-escape them as a
  // defense in depth against future template changes.
  lookup.set("primaryColor", escapeXml(branding.primaryColor));
  lookup.set("accentColor", escapeXml(branding.accentColor));

  if (branding.logoDataUri) {
    lookup.set("logoDataUri", branding.logoDataUri);
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

/**
 * Collapse the legacy customization fields and the new `branding` field
 * into a single `IssuerBranding` payload. Explicit `primaryColor`,
 * `accentColor`, and `logoDataUri` fields on the customization object
 * override the issuer's `branding` defaults.
 */
function mergeCustomization(
  customization: TemplateCustomization | undefined,
): IssuerBranding | undefined {
  if (!customization) return undefined;

  const branding: IssuerBranding = { ...customization.branding };

  if (customization.primaryColor !== undefined) {
    branding.primaryColor = customization.primaryColor;
  }
  if (customization.accentColor !== undefined) {
    branding.accentColor = customization.accentColor;
  }
  if (customization.logoDataUri !== undefined) {
    branding.logoDataUri = customization.logoDataUri;
  }

  // If nothing was set, return undefined so resolveBranding falls through
  // to defaults instead of carrying an empty object.
  if (
    branding.primaryColor === undefined &&
    branding.accentColor === undefined &&
    branding.logoDataUri === undefined
  ) {
    return undefined;
  }

  return branding;
}

/** Re-exported for callers that want to read the renderer defaults. */
export { DEFAULT_PRIMARY_COLOR, DEFAULT_ACCENT_COLOR };

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
