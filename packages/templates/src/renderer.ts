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
 *
 * SECURITY:
 *
 * Every credential-derived value inserted into the template is escaped or
 * validated for the context it lands in. SVG, when opened in a browser,
 * is an active document that can run script (`<script>`, `on*` handlers,
 * `xlink:href="javascript:..."`, CSS `url(javascript:...)`, ...) — so a
 * hostile credential whose `issuer.name` or `type[]` contains
 * `</text><script>...</script><text>` would trivially run script in a
 * recipient's browser if we interpolated raw strings.
 *
 *   - Text content (`credentialTitle`, `issuerName`, `validFrom`,
 *     `validUntil`, `subject.*`): XML-escaped via `escapeXml`. The same
 *     escape covers `<`, `>`, `&`, `"`, `'` which is sufficient for both
 *     text content AND attribute values.
 *   - Logo data URI (`logoDataUri`, attribute context): re-validated by
 *     `validateLogoDataUri` here too (NOT only by `resolveBranding`), so
 *     the renderer fails closed even when called via a future code path
 *     that bypasses the branding pipeline. Anything that is not a base64
 *     `data:image/png` or `data:image/svg+xml` URI is dropped.
 *   - QR code (`qrCode`, attribute context): subject to the same `data:`
 *     URI validation, with a wider MIME-type policy because the QR module
 *     emits PNG/SVG/JPEG.
 *   - Primary/accent colors (`primaryColor`, `accentColor`, CSS context):
 *     re-validated by the renderer with `isValidHexColor`. Anything that
 *     does not match `^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$` falls back to
 *     the OpenCred default. CSS escape would not be enough here —
 *     `red; } body { background: url(javascript:...) } /*` is a valid CSS
 *     string after XML escaping but breaks out of the rule.
 */

import type { IssuerBranding, RenderOptions, TemplateCustomization } from "./types.js";
import {
  DEFAULT_ACCENT_COLOR,
  DEFAULT_PRIMARY_COLOR,
  isValidHexColor,
  resolveBranding,
  validateLogoDataUri,
} from "./branding.js";

const PLACEHOLDER_RE = /\{\{([^#/}]+?)\}\}/g;
const CONDITIONAL_RE = /\{\{#(\w+)\}\}([\s\S]*?)\{\{\/\1\}\}/g;

/**
 * MIME types accepted for the QR code data URI. The QR module currently
 * emits PNG, but SVG and JPEG are accepted for forward compatibility.
 * Other types (especially `text/html`, `application/javascript`, ...)
 * are rejected so a future caller cannot smuggle active content via the
 * QR placeholder.
 */
const ALLOWED_QR_MIME_TYPES: ReadonlySet<string> = new Set([
  "image/png",
  "image/svg+xml",
  "image/jpeg",
]);

/** Maximum size of a QR data URI in bytes (1.5 MB, matches the logo limit). */
const MAX_QR_DATA_URI_BYTES = 1.5 * 1024 * 1024;

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

  // Resolve branding overrides into a flat, validated payload. The renderer
  // ALSO re-validates each placeholder below as a defense-in-depth measure
  // against future code paths that might bypass `resolveBranding`.
  const merged = mergeCustomization(customization);
  const branding = resolveBranding(merged);

  // Build a flat lookup map for placeholders
  const lookup = new Map<string, string>();

  // Text-content placeholders. Escape every credential-derived value so a
  // hostile `issuer.name` or `type[1]` cannot inject markup.
  lookup.set("issuerName", escapeXml(values.issuerName));
  lookup.set("credentialTitle", escapeXml(values.credentialTitle));
  lookup.set("validFrom", escapeXml(formatDate(values.validFrom)));
  lookup.set(
    "validUntil",
    escapeXml(values.validUntil ? formatDate(values.validUntil) : "No expiry"),
  );

  // Subject fields — escaped for SVG text/attribute context.
  for (const [key, val] of Object.entries(values.subject)) {
    lookup.set(`subject.${key}`, escapeXml(val));
  }

  // QR code lands inside an attribute (`href="{{qrCode}}"`). It must be a
  // safe `data:` URI of a known image MIME type, otherwise we drop it (and
  // the conditional `{{#qrCode}}...{{/qrCode}}` collapses).
  if (
    values.qrCode &&
    isSafeDataUri(values.qrCode, ALLOWED_QR_MIME_TYPES, MAX_QR_DATA_URI_BYTES)
  ) {
    lookup.set("qrCode", escapeXml(values.qrCode));
  }

  // CSS-context placeholders. We validate strictly against the hex color
  // grammar — XML-escaping alone would not stop CSS injection like
  // `red; } body { background: url(javascript:...) } /*`.
  lookup.set("primaryColor", safeCssColor(branding.primaryColor, DEFAULT_PRIMARY_COLOR));
  lookup.set("accentColor", safeCssColor(branding.accentColor, DEFAULT_ACCENT_COLOR));

  // Logo data URI lands inside an attribute. Even though `resolveBranding`
  // already validated it, we re-run the validator here so a future code
  // path that bypasses the branding pipeline cannot smuggle a remote URL
  // (e.g. `https://evil.example/x.svg`) into the rendered output.
  if (
    branding.logoDataUri &&
    validateLogoDataUri(branding.logoDataUri).ok
  ) {
    lookup.set("logoDataUri", escapeXml(branding.logoDataUri));
  }

  // Issuer display name (customization-only) overrides the issuer's DID.
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
 * Validate a `data:` URI against an allowed set of MIME types and a maximum
 * length. Returns true iff the URI is safe to interpolate into a `href` /
 * `src` attribute. Used for QR codes (and as a backstop for logos).
 */
function isSafeDataUri(
  value: string,
  allowedMimeTypes: ReadonlySet<string>,
  maxBytes: number,
): boolean {
  if (typeof value !== "string") return false;
  if (value.length > maxBytes) return false;
  if (!value.startsWith("data:")) return false;
  // Match `data:<mime>;base64,<payload>` and reject anything else. We
  // require base64 because raw payloads can carry XML/SVG markup.
  const match = /^data:([a-zA-Z0-9.+/-]+);base64,([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (!match) return false;
  return allowedMimeTypes.has(match[1].toLowerCase());
}

/**
 * Return a safe CSS color string. Accepts only validated hex colors via
 * `isValidHexColor`; falls back to `fallback` for anything else. Defense
 * in depth above and beyond `resolveBranding` so the renderer cannot leak
 * arbitrary CSS even if its caller bypasses the branding pipeline.
 */
function safeCssColor(value: string | undefined, fallback: string): string {
  if (value && isValidHexColor(value)) {
    return value;
  }
  return fallback;
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

/**
 * Escape XML special characters for SVG text content and attribute values.
 *
 * SVG, when opened in a browser, is an active document. The same five
 * characters need escaping for both text content and double-quoted
 * attribute values: `&`, `<`, `>`, `"`, `'`. We always emit named
 * entities so the output is valid XML.
 */
function escapeXml(str: string): string {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}
