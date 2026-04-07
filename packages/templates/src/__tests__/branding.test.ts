/**
 * Tests for issuer branding helpers.
 *
 * Validates color parsing, logo data URI validation, SVG sanitization,
 * and branding resolution against the OpenCred defaults.
 */

import { describe, it, expect } from "vitest";
import {
  ALLOWED_LOGO_MIME_TYPES,
  DEFAULT_ACCENT_COLOR,
  DEFAULT_PRIMARY_COLOR,
  MAX_LOGO_DATA_URI_BYTES,
  isValidHexColor,
  normalizeHexColor,
  resolveBranding,
  sanitizeSvgLogo,
  svgToDataUri,
  validateLogoDataUri,
} from "../branding.js";

// ──────────────────────────────────────────────────────────────────
// Hex colors
// ──────────────────────────────────────────────────────────────────

describe("isValidHexColor", () => {
  it.each(["#000", "#fff", "#FFF", "#abc", "#ABC", "#000000", "#ffffff", "#1a56db", "#1A56DB"])(
    "accepts valid hex %s",
    (input) => {
      expect(isValidHexColor(input)).toBe(true);
    },
  );

  it.each([
    "",
    "1a56db",
    "#",
    "#1a56d",
    "#1a56db1",
    "#1a56dbff",
    "#xyzxyz",
    "#1a 56db",
    "rgb(255, 0, 0)",
    "red",
  ])("rejects invalid hex %s", (input) => {
    expect(isValidHexColor(input)).toBe(false);
  });

  it("rejects non-strings", () => {
    expect(isValidHexColor(undefined)).toBe(false);
    expect(isValidHexColor(null)).toBe(false);
    expect(isValidHexColor(123 as unknown)).toBe(false);
    expect(isValidHexColor({} as unknown)).toBe(false);
  });
});

describe("normalizeHexColor", () => {
  it("expands 3-digit shorthand", () => {
    expect(normalizeHexColor("#abc")).toBe("#aabbcc");
  });

  it("lowercases 6-digit", () => {
    expect(normalizeHexColor("#1A56DB")).toBe("#1a56db");
  });

  it("returns undefined for invalid input", () => {
    expect(normalizeHexColor("not-a-color")).toBeUndefined();
    expect(normalizeHexColor(undefined)).toBeUndefined();
  });
});

// ──────────────────────────────────────────────────────────────────
// Logo data URI validation
// ──────────────────────────────────────────────────────────────────

describe("validateLogoDataUri", () => {
  // 1x1 transparent PNG, ~70 bytes when raw
  const TINY_PNG_BASE64 =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=";
  const VALID_PNG_DATA_URI = `data:image/png;base64,${TINY_PNG_BASE64}`;

  it("accepts a valid PNG data URI", () => {
    const result = validateLogoDataUri(VALID_PNG_DATA_URI);
    expect(result.ok).toBe(true);
    expect(result.mimeType).toBe("image/png");
  });

  it("accepts a valid SVG data URI", () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>';
    const dataUri = svgToDataUri(svg);
    const result = validateLogoDataUri(dataUri);
    expect(result.ok).toBe(true);
    expect(result.mimeType).toBe("image/svg+xml");
  });

  it("rejects http(s) URLs", () => {
    const result = validateLogoDataUri("https://example.com/logo.png");
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/data: URI/);
  });

  it("rejects relative paths", () => {
    const result = validateLogoDataUri("./logo.png");
    expect(result.ok).toBe(false);
  });

  it("rejects unsupported MIME types (jpeg)", () => {
    // Build a minimal data URI with image/jpeg.
    const dataUri = "data:image/jpeg;base64,YWJj";
    const result = validateLogoDataUri(dataUri);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/not allowed/);
  });

  it("rejects gif", () => {
    const dataUri = "data:image/gif;base64,YWJj";
    expect(validateLogoDataUri(dataUri).ok).toBe(false);
  });

  it("rejects malformed base64 payloads", () => {
    const dataUri = "data:image/png;base64,not!base64@here";
    expect(validateLogoDataUri(dataUri).ok).toBe(false);
  });

  it("rejects oversize payloads", () => {
    // Build a string longer than the byte cap.
    const oversize = "data:image/png;base64," + "a".repeat(MAX_LOGO_DATA_URI_BYTES);
    expect(validateLogoDataUri(oversize).ok).toBe(false);
  });

  it("rejects non-strings", () => {
    expect(validateLogoDataUri(undefined).ok).toBe(false);
    expect(validateLogoDataUri(null).ok).toBe(false);
    expect(validateLogoDataUri(42 as unknown).ok).toBe(false);
  });

  it("ALLOWED_LOGO_MIME_TYPES contains the documented set", () => {
    expect(ALLOWED_LOGO_MIME_TYPES.has("image/png")).toBe(true);
    expect(ALLOWED_LOGO_MIME_TYPES.has("image/svg+xml")).toBe(true);
    expect(ALLOWED_LOGO_MIME_TYPES.has("image/jpeg")).toBe(false);
  });
});

// ──────────────────────────────────────────────────────────────────
// SVG sanitization
// ──────────────────────────────────────────────────────────────────

describe("sanitizeSvgLogo", () => {
  it("accepts a benign SVG", () => {
    const input = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10" fill="red" /></svg>';
    const result = sanitizeSvgLogo(input);
    expect(result.ok).toBe(true);
    expect(result.svg).toContain("<rect");
    expect(result.svg).toContain("<svg");
  });

  it("strips <script> elements", () => {
    const hostile = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><rect /></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("<script");
    expect(result.svg).not.toContain("alert(1)");
    expect(result.svg).toContain("<rect");
  });

  it("strips <foreignObject> elements", () => {
    const hostile =
      '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div>html</div></foreignObject></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("foreignObject");
    expect(result.svg).not.toContain("<div");
  });

  it("strips inline event handlers", () => {
    const hostile = '<svg xmlns="http://www.w3.org/2000/svg"><rect onclick="alert(1)" onload=\'go()\' /></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toMatch(/onclick/i);
    expect(result.svg).not.toMatch(/onload/i);
    expect(result.svg).toContain("<rect");
  });

  it("strips external href attributes from <use>", () => {
    const hostile =
      '<svg xmlns="http://www.w3.org/2000/svg"><use xlink:href="https://evil.example/x.svg#a" /></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("evil.example");
  });

  it("preserves data: URI hrefs on <image>", () => {
    const benign =
      '<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,abc" /></svg>';
    const result = sanitizeSvgLogo(benign);
    expect(result.ok).toBe(true);
    expect(result.svg).toContain("data:image/png;base64,abc");
  });

  it("preserves fragment-identifier hrefs on <use>", () => {
    const benign = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="x"/></defs><use href="#x" /></svg>';
    const result = sanitizeSvgLogo(benign);
    expect(result.ok).toBe(true);
    expect(result.svg).toContain('href="#x"');
  });

  it("strips DOCTYPE declarations", () => {
    const hostile = '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://example.com/dtd"><svg xmlns="http://www.w3.org/2000/svg"></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("DOCTYPE");
  });

  it("strips XML processing instructions", () => {
    const hostile = '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("<?xml");
  });

  it("strips XML comments", () => {
    const hostile = '<svg xmlns="http://www.w3.org/2000/svg"><!-- evil comment --><rect /></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("<!--");
    expect(result.svg).not.toContain("evil comment");
  });

  it("strips CDATA blocks", () => {
    const hostile = '<svg xmlns="http://www.w3.org/2000/svg"><![CDATA[evil]]><rect /></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("CDATA");
    expect(result.svg).not.toContain("evil");
  });

  it("strips <style> elements", () => {
    const hostile =
      '<svg xmlns="http://www.w3.org/2000/svg"><style>@import url(http://evil/) ;</style><rect /></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("<style");
    expect(result.svg).not.toContain("@import");
  });

  it("strips animation elements", () => {
    const hostile =
      '<svg xmlns="http://www.w3.org/2000/svg"><animate attributeName="x" values="0;100" /><rect /></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("<animate");
  });

  it("rejects empty input", () => {
    expect(sanitizeSvgLogo("").ok).toBe(false);
  });

  it("rejects non-SVG input", () => {
    const result = sanitizeSvgLogo("<div>not svg</div>");
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/svg/i);
  });

  it("rejects oversize input", () => {
    const huge = "<svg>" + "a".repeat(MAX_LOGO_DATA_URI_BYTES + 1) + "</svg>";
    expect(sanitizeSvgLogo(huge).ok).toBe(false);
  });

  it("removes nested <script> elements", () => {
    const hostile = '<svg xmlns="http://www.w3.org/2000/svg"><g><script>x</script></g></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("<script");
  });

  it("strips <iframe> embedding", () => {
    const hostile = '<svg xmlns="http://www.w3.org/2000/svg"><iframe src="javascript:alert(1)"></iframe></svg>';
    const result = sanitizeSvgLogo(hostile);
    expect(result.ok).toBe(true);
    expect(result.svg).not.toContain("<iframe");
    expect(result.svg).not.toContain("javascript:");
  });
});

// ──────────────────────────────────────────────────────────────────
// svgToDataUri
// ──────────────────────────────────────────────────────────────────

describe("svgToDataUri", () => {
  it("produces a base64 data URI with the SVG MIME type", () => {
    const svg = "<svg></svg>";
    const dataUri = svgToDataUri(svg);
    expect(dataUri.startsWith("data:image/svg+xml;base64,")).toBe(true);
    const b64 = dataUri.split(",")[1];
    const decoded = Buffer.from(b64, "base64").toString("utf8");
    expect(decoded).toBe(svg);
  });

  it("round-trips through validateLogoDataUri", () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>';
    const dataUri = svgToDataUri(svg);
    expect(validateLogoDataUri(dataUri).ok).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────────────
// resolveBranding
// ──────────────────────────────────────────────────────────────────

describe("resolveBranding", () => {
  it("returns OpenCred defaults when branding is undefined", () => {
    const branding = resolveBranding(undefined);
    expect(branding.primaryColor).toBe(DEFAULT_PRIMARY_COLOR);
    expect(branding.accentColor).toBe(DEFAULT_ACCENT_COLOR);
    expect(branding.logoDataUri).toBeNull();
  });

  it("returns OpenCred defaults when branding is empty", () => {
    const branding = resolveBranding({});
    expect(branding.primaryColor).toBe(DEFAULT_PRIMARY_COLOR);
    expect(branding.accentColor).toBe(DEFAULT_ACCENT_COLOR);
    expect(branding.logoDataUri).toBeNull();
  });

  it("applies valid hex colors", () => {
    const branding = resolveBranding({ primaryColor: "#ff0000", accentColor: "#00ff00" });
    expect(branding.primaryColor).toBe("#ff0000");
    expect(branding.accentColor).toBe("#00ff00");
  });

  it("expands 3-digit hex colors", () => {
    const branding = resolveBranding({ primaryColor: "#f00" });
    expect(branding.primaryColor).toBe("#ff0000");
  });

  it("falls back to defaults for invalid hex", () => {
    const branding = resolveBranding({ primaryColor: "not-a-color", accentColor: "#zzzzzz" });
    expect(branding.primaryColor).toBe(DEFAULT_PRIMARY_COLOR);
    expect(branding.accentColor).toBe(DEFAULT_ACCENT_COLOR);
  });

  it("retains a valid logo data URI", () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"></svg>';
    const dataUri = svgToDataUri(svg);
    const branding = resolveBranding({ logoDataUri: dataUri });
    expect(branding.logoDataUri).toBe(dataUri);
  });

  it("drops a remote URL logo", () => {
    const branding = resolveBranding({ logoDataUri: "https://evil.example/logo.png" });
    expect(branding.logoDataUri).toBeNull();
  });

  it("drops an oversize logo", () => {
    const oversize = "data:image/png;base64," + "a".repeat(MAX_LOGO_DATA_URI_BYTES);
    const branding = resolveBranding({ logoDataUri: oversize });
    expect(branding.logoDataUri).toBeNull();
  });
});
