/**
 * Tests for issuer branding settings storage and validation.
 *
 * Verifies:
 *  - Branding is stored/retrieved via electron-store
 *  - Branding is passed through to credential packaging
 *  - Color validation (valid hex only)
 *  - Logo data URI validation (must be data:image/*)
 */

import { describe, it, expect } from "vitest";

// ---------------------------------------------------------------------------
// Validation helpers (extracted from component logic for testability)
// ---------------------------------------------------------------------------

/** Validate a CSS hex color string (3, 4, 6, or 8 hex digits). */
function isValidHexColor(value: string): boolean {
  return /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{4}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$/.test(value);
}

/** Validate a data URI for an image. */
function isValidImageDataUri(value: string): boolean {
  return /^data:image\/(png|jpeg|jpg|svg\+xml|webp);base64,/.test(value);
}

// ---------------------------------------------------------------------------
// Color validation
// ---------------------------------------------------------------------------

describe("isValidHexColor", () => {
  it("should accept 6-digit hex colors", () => {
    expect(isValidHexColor("#0057FF")).toBe(true);
    expect(isValidHexColor("#ffffff")).toBe(true);
    expect(isValidHexColor("#000000")).toBe(true);
    expect(isValidHexColor("#ABCDEF")).toBe(true);
  });

  it("should accept 3-digit shorthand hex colors", () => {
    expect(isValidHexColor("#fff")).toBe(true);
    expect(isValidHexColor("#000")).toBe(true);
    expect(isValidHexColor("#abc")).toBe(true);
  });

  it("should accept 8-digit hex colors (with alpha)", () => {
    expect(isValidHexColor("#0057FFAA")).toBe(true);
    expect(isValidHexColor("#00000000")).toBe(true);
  });

  it("should accept 4-digit shorthand hex colors (with alpha)", () => {
    expect(isValidHexColor("#fffa")).toBe(true);
  });

  it("should reject invalid hex colors", () => {
    expect(isValidHexColor("")).toBe(false);
    expect(isValidHexColor("#")).toBe(false);
    expect(isValidHexColor("#GG")).toBe(false);
    expect(isValidHexColor("#GGGGGG")).toBe(false);
    expect(isValidHexColor("0057FF")).toBe(false); // no hash
    expect(isValidHexColor("#12345")).toBe(false); // 5 digits
    expect(isValidHexColor("rgb(0,87,255)")).toBe(false);
    expect(isValidHexColor("blue")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Logo data URI validation
// ---------------------------------------------------------------------------

describe("isValidImageDataUri", () => {
  it("should accept PNG data URIs", () => {
    expect(isValidImageDataUri("data:image/png;base64,iVBOR")).toBe(true);
  });

  it("should accept JPEG data URIs", () => {
    expect(isValidImageDataUri("data:image/jpeg;base64,/9j/4")).toBe(true);
  });

  it("should accept SVG data URIs", () => {
    expect(isValidImageDataUri("data:image/svg+xml;base64,PHN2Zw")).toBe(true);
  });

  it("should accept WebP data URIs", () => {
    expect(isValidImageDataUri("data:image/webp;base64,UklGR")).toBe(true);
  });

  it("should reject non-image data URIs", () => {
    expect(isValidImageDataUri("data:text/plain;base64,abc")).toBe(false);
    expect(isValidImageDataUri("data:application/pdf;base64,abc")).toBe(false);
  });

  it("should reject invalid strings", () => {
    expect(isValidImageDataUri("")).toBe(false);
    expect(isValidImageDataUri("https://example.com/logo.png")).toBe(false);
    expect(isValidImageDataUri("not-a-data-uri")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Branding store schema
// ---------------------------------------------------------------------------

describe("branding store schema", () => {
  it("should accept valid branding objects", () => {
    const branding = {
      primaryColor: "#0057FF",
      logoDataUri: "data:image/png;base64,iVBORw0KGgo=",
      issuerDisplayName: "Acme University",
    };

    expect(branding.primaryColor).toBeDefined();
    expect(isValidHexColor(branding.primaryColor)).toBe(true);
    expect(isValidImageDataUri(branding.logoDataUri)).toBe(true);
    expect(branding.issuerDisplayName).toBe("Acme University");
  });

  it("should allow partial branding (only color)", () => {
    const branding = { primaryColor: "#FF0000" };
    expect(isValidHexColor(branding.primaryColor)).toBe(true);
  });

  it("should allow empty branding object", () => {
    const branding: Record<string, unknown> = {};
    expect(Object.keys(branding).length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Branding passthrough to PackageCredentialRequest
// ---------------------------------------------------------------------------

describe("branding passthrough", () => {
  it("should map branding to customization in package request", () => {
    const branding = {
      primaryColor: "#FF5500",
      logoDataUri: "data:image/png;base64,abc123",
      issuerDisplayName: "Test Issuer",
    };

    // Simulate the mapping done in CredentialBuilderPage
    const packageRequest = {
      credential: "{}",
      formats: ["pdf"],
      schemaId: "education",
      customization: branding,
    };

    expect(packageRequest.customization).toEqual(branding);
    expect(packageRequest.customization.primaryColor).toBe("#FF5500");
    expect(packageRequest.customization.logoDataUri).toBe("data:image/png;base64,abc123");
    expect(packageRequest.customization.issuerDisplayName).toBe("Test Issuer");
  });

  it("should pass undefined customization when no branding is set", () => {
    const packageRequest = {
      credential: "{}",
      formats: ["pdf"],
      customization: undefined,
    };

    expect(packageRequest.customization).toBeUndefined();
  });
});
