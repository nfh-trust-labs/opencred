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

/**
 * Render an SVG template with the given values and customization.
 */
export function renderSvg(svgTemplate: string, options: RenderOptions): string {
  const { values, customization } = options;

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

  // Customization
  const primaryColor = customization?.primaryColor ?? DEFAULT_PRIMARY_COLOR;
  lookup.set("primaryColor", escapeXml(primaryColor));

  if (customization?.logoDataUri) {
    lookup.set("logoDataUri", customization.logoDataUri);
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
