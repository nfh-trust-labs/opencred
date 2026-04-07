/**
 * Tests for issuer branding — main-process validation, sanitization, and
 * persistence helpers.
 *
 * The store is mocked so these tests run without an Electron environment.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock electron-store before importing the store / branding modules.
let mockBranding: unknown = undefined;
const mockGet = vi.fn((key: string) => {
  if (key === "issuerBranding") return mockBranding;
  return undefined;
});
const mockSet = vi.fn((key: string, value: unknown) => {
  if (key === "issuerBranding") mockBranding = value;
});
const mockDelete = vi.fn((key: string) => {
  if (key === "issuerBranding") mockBranding = undefined;
});
const mockStore = {
  get: mockGet,
  set: mockSet,
  delete: mockDelete,
  store: {},
  path: "/tmp/test-store.json",
};

vi.mock("electron-store", () => ({
  default: vi.fn().mockImplementation(() => mockStore),
}));

// 1x1 transparent PNG (no metadata chunks)
const TINY_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=";

// 1x1 PNG with a tEXt chunk containing "Comment\0evil text"
function pngWithTextChunk(): Buffer {
  // Base PNG bytes (decoded once)
  const basePng = Buffer.from(TINY_PNG_BASE64, "base64");
  // Find IEND offset (last 12 bytes: length(0)+IEND+crc)
  const iendOffset = basePng.length - 12;
  const beforeIend = basePng.subarray(0, iendOffset);
  const iendChunk = basePng.subarray(iendOffset);

  // Build a tEXt chunk: keyword "Comment" \0 text "evil"
  const data = Buffer.concat([
    Buffer.from("Comment\0evil text", "ascii"),
  ]);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const type = Buffer.from("tEXt", "ascii");
  // CRC: zero is fine — parsers don't validate CRC for ancillary chunks
  const crc = Buffer.alloc(4);

  return Buffer.concat([beforeIend, length, type, data, crc, iendChunk]);
}

const { initStore } = await import("../main/store");
initStore();

const {
  processLogoFile,
  handleBrandingGet,
  handleBrandingSet,
  handleBrandingClear,
  getActiveBranding,
  MAX_LOGO_DIMENSION,
} = await import("../main/branding");

describe("processLogoFile", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBranding = undefined;
  });

  it("accepts a valid PNG", () => {
    const result = processLogoFile({
      mimeType: "image/png",
      base64: TINY_PNG_BASE64,
    });
    expect(result.ok).toBe(true);
    expect(result.mimeType).toBe("image/png");
    expect(result.dataUri).toMatch(/^data:image\/png;base64,/);
  });

  it("accepts a valid SVG and sanitizes it", () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>';
    const result = processLogoFile({
      mimeType: "image/svg+xml",
      base64: Buffer.from(svg, "utf8").toString("base64"),
    });
    expect(result.ok).toBe(true);
    expect(result.mimeType).toBe("image/svg+xml");
    expect(result.dataUri).toMatch(/^data:image\/svg\+xml;base64,/);
  });

  it("strips PNG metadata (tEXt chunk) before persisting", () => {
    const pngWithMetadata = pngWithTextChunk();
    expect(pngWithMetadata.toString("ascii")).toContain("evil text");

    const result = processLogoFile({
      mimeType: "image/png",
      base64: pngWithMetadata.toString("base64"),
    });

    expect(result.ok).toBe(true);
    // Decode the persisted base64 and verify the metadata is gone.
    const b64 = result.dataUri!.split(",")[1];
    const decoded = Buffer.from(b64, "base64");
    expect(decoded.toString("ascii")).not.toContain("evil text");
    expect(decoded.toString("ascii")).not.toContain("Comment");
  });

  it("strips <script> from uploaded SVGs", () => {
    const hostile = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><rect/></svg>';
    const result = processLogoFile({
      mimeType: "image/svg+xml",
      base64: Buffer.from(hostile, "utf8").toString("base64"),
    });
    expect(result.ok).toBe(true);
    const decoded = Buffer.from(result.dataUri!.split(",")[1], "base64").toString("utf8");
    expect(decoded).not.toContain("<script");
    expect(decoded).not.toContain("alert(1)");
  });

  it("strips event handlers from uploaded SVGs", () => {
    const hostile = '<svg xmlns="http://www.w3.org/2000/svg"><rect onclick="alert(1)" onload="hi"/></svg>';
    const result = processLogoFile({
      mimeType: "image/svg+xml",
      base64: Buffer.from(hostile, "utf8").toString("base64"),
    });
    expect(result.ok).toBe(true);
    const decoded = Buffer.from(result.dataUri!.split(",")[1], "base64").toString("utf8");
    expect(decoded).not.toContain("onclick");
    expect(decoded).not.toContain("onload");
  });

  it("rejects JPEG MIME type", () => {
    const result = processLogoFile({
      mimeType: "image/jpeg",
      base64: "AAAA",
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/not allowed/);
  });

  it("rejects empty payloads", () => {
    const result = processLogoFile({
      mimeType: "image/png",
      base64: "",
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/empty/);
  });

  it("rejects payloads exceeding 1 MB", () => {
    // Build a 1.1 MB byte buffer.
    const big = Buffer.alloc(1.1 * 1024 * 1024, 0xff);
    const result = processLogoFile({
      mimeType: "image/png",
      base64: big.toString("base64"),
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/limit/);
  });

  it("rejects PNGs without a valid PNG signature", () => {
    const fake = Buffer.from("not a real png at all but long enough", "ascii");
    const result = processLogoFile({
      mimeType: "image/png",
      base64: fake.toString("base64"),
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/PNG/);
  });

  it("rejects PNGs above the dimension cap", () => {
    // Build a fake PNG with 2048x2048 dimensions in IHDR.
    const pngSig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const ihdrLen = Buffer.alloc(4);
    ihdrLen.writeUInt32BE(13, 0);
    const ihdrType = Buffer.from("IHDR", "ascii");
    const ihdrData = Buffer.alloc(13);
    ihdrData.writeUInt32BE(2048, 0);
    ihdrData.writeUInt32BE(2048, 4);
    const ihdrCrc = Buffer.alloc(4);
    const buf = Buffer.concat([pngSig, ihdrLen, ihdrType, ihdrData, ihdrCrc]);

    const result = processLogoFile({
      mimeType: "image/png",
      base64: buf.toString("base64"),
    });
    expect(result.ok).toBe(false);
    expect(result.error).toContain(`${MAX_LOGO_DIMENSION}`);
  });

  it("rejects SVG that has no <svg> root", () => {
    const result = processLogoFile({
      mimeType: "image/svg+xml",
      base64: Buffer.from("<div>not svg</div>", "utf8").toString("base64"),
    });
    expect(result.ok).toBe(false);
  });
});

describe("handleBrandingSet / handleBrandingGet / handleBrandingClear", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBranding = undefined;
  });

  it("returns configured: false when nothing is persisted", () => {
    const result = handleBrandingGet();
    expect(result.configured).toBe(false);
    expect(result.branding).toBeUndefined();
  });

  it("persists colors only", () => {
    const result = handleBrandingSet({
      primaryColor: "#ff0000",
      accentColor: "#00ff00",
    });
    expect(result.success).toBe(true);
    expect(result.branding?.primaryColor).toBe("#ff0000");
    expect(result.branding?.accentColor).toBe("#00ff00");
    expect(result.updatedAt).toBeDefined();
  });

  it("persists a logo file alongside colors", () => {
    const result = handleBrandingSet({
      primaryColor: "#1a56db",
      accentColor: "#0ea5e9",
      logoFile: { mimeType: "image/png", base64: TINY_PNG_BASE64 },
    });
    expect(result.success).toBe(true);
    expect(result.branding?.logoDataUri).toMatch(/^data:image\/png;base64,/);
  });

  it("rejects an invalid hex primary color", () => {
    const result = handleBrandingSet({ primaryColor: "red" });
    expect(result.success).toBe(false);
    expect(result.errorField).toBe("primaryColor");
  });

  it("rejects an invalid hex accent color", () => {
    const result = handleBrandingSet({ accentColor: "#zzzzzz" });
    expect(result.success).toBe(false);
    expect(result.errorField).toBe("accentColor");
  });

  it("rejects an unsupported logo MIME type", () => {
    const result = handleBrandingSet({
      logoFile: { mimeType: "image/jpeg", base64: "AAAA" },
    });
    expect(result.success).toBe(false);
    expect(result.errorField).toBe("logo");
  });

  it("supports partial updates (color only) without erasing the logo", () => {
    handleBrandingSet({
      primaryColor: "#1a56db",
      logoFile: { mimeType: "image/png", base64: TINY_PNG_BASE64 },
    });

    const result = handleBrandingSet({ accentColor: "#0ea5e9" });
    expect(result.success).toBe(true);
    expect(result.branding?.logoDataUri).toBeDefined();
    expect(result.branding?.primaryColor).toBe("#1a56db");
    expect(result.branding?.accentColor).toBe("#0ea5e9");
  });

  it("supports removeLogo without erasing the colors", () => {
    handleBrandingSet({
      primaryColor: "#1a56db",
      accentColor: "#0ea5e9",
      logoFile: { mimeType: "image/png", base64: TINY_PNG_BASE64 },
    });

    const result = handleBrandingSet({ removeLogo: true });
    expect(result.success).toBe(true);
    expect(result.branding?.logoDataUri).toBeUndefined();
    expect(result.branding?.primaryColor).toBe("#1a56db");
    expect(result.branding?.accentColor).toBe("#0ea5e9");
  });

  it("normalizes hex shorthand to 6-digit", () => {
    const result = handleBrandingSet({ primaryColor: "#abc" });
    expect(result.success).toBe(true);
    expect(result.branding?.primaryColor).toBe("#aabbcc");
  });

  it("clears all branding", () => {
    handleBrandingSet({ primaryColor: "#ff0000" });
    expect(handleBrandingGet().configured).toBe(true);

    const cleared = handleBrandingClear();
    expect(cleared.success).toBe(true);
    expect(handleBrandingGet().configured).toBe(false);
  });
});

describe("getActiveBranding", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBranding = undefined;
  });

  it("returns undefined when no branding is set", () => {
    expect(getActiveBranding()).toBeUndefined();
  });

  it("returns a branding payload when configured", () => {
    handleBrandingSet({
      primaryColor: "#1a56db",
      accentColor: "#0ea5e9",
    });
    const branding = getActiveBranding();
    expect(branding?.primaryColor).toBe("#1a56db");
    expect(branding?.accentColor).toBe("#0ea5e9");
  });

  it("includes the logo when one is persisted", () => {
    handleBrandingSet({
      logoFile: { mimeType: "image/png", base64: TINY_PNG_BASE64 },
    });
    const branding = getActiveBranding();
    expect(branding?.logoDataUri).toMatch(/^data:image\/png;base64,/);
  });
});
