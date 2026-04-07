/**
 * End-to-end smoke test: persist issuer branding, then render a credential
 * SVG and verify the resulting markup contains the configured logo data
 * URI and color values.
 *
 * Uses the REAL `@opencred/templates` package (no mock) so the test
 * exercises the full pipeline:
 *
 *   handleBrandingSet()
 *     → store
 *   getActiveBranding()
 *     → renderSvg() (with built-in `default` template)
 *       → SVG output containing logo data URI + brand colors
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

let mockBranding: unknown = undefined;
const mockGet = vi.fn((key: string) => (key === "issuerBranding" ? mockBranding : undefined));
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

const { initStore } = await import("../main/store");
initStore();

const { handleBrandingSet, handleBrandingClear, getActiveBranding } = await import(
  "../main/branding"
);
const { renderCredentialSvg } = await import("../main/credential-export");
import type { VerifiableCredential } from "@opencred/vc-core";

const BRANDED_CREDENTIAL: VerifiableCredential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:branded-test",
  type: ["VerifiableCredential", "EducationCredential"],
  issuer: { id: "did:key:z6MkBranded", name: "Branded University" },
  validFrom: "2026-01-15T00:00:00Z",
  validUntil: "2027-01-15T00:00:00Z",
  credentialSubject: {
    id: "did:key:z6MkStudent",
    name: "Jane Doe",
    degree: "Bachelor of Science",
    institution: "MIT",
    dateConferred: "2025-06-15",
  },
  proof: {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-rdfc-2019",
    created: "2026-01-15T00:00:00Z",
    verificationMethod: "did:key:z6MkBranded#z6MkBranded",
    proofPurpose: "assertionMethod",
    proofValue: "z3FXQqFhWGuKocnMiM3pyU8gyL3J1vYGjyDz3hXsaHvhP",
  },
};

// 1x1 transparent PNG, ~70 bytes raw — embedded so we can match against it.
const TINY_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=";

describe("end-to-end issuer branding rendering", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBranding = undefined;
  });

  it("renders an unbranded credential with OpenCred default colors", () => {
    const branding = getActiveBranding();
    expect(branding).toBeUndefined();

    const svg = renderCredentialSvg(BRANDED_CREDENTIAL, "education", branding ? { branding } : undefined);

    expect(svg).toContain("Jane Doe");
    expect(svg).toContain("Branded University");
    expect(svg).toContain("Bachelor of Science");
    expect(svg).toContain("#1a56db"); // default primary
    expect(svg).toContain("#0ea5e9"); // default accent
  });

  it("renders a branded credential with the configured colors and logo", () => {
    handleBrandingSet({
      primaryColor: "#fa8072",
      accentColor: "#9333ea",
      logoFile: { mimeType: "image/png", base64: TINY_PNG_BASE64 },
    });

    const branding = getActiveBranding();
    expect(branding).toBeDefined();

    const svg = renderCredentialSvg(BRANDED_CREDENTIAL, "education", { branding });

    // Subject data still rendered as usual
    expect(svg).toContain("Jane Doe");
    expect(svg).toContain("Branded University");

    // Brand colors applied
    expect(svg).toContain("#fa8072");
    expect(svg).toContain("#9333ea");
    expect(svg).not.toContain("#1a56db");

    // Logo embedded as a data URI
    expect(svg).toMatch(/data:image\/png;base64,/);

    // Defense in depth: no scripts in the rendered output. The only HTTP
    // reference allowed is the SVG XML namespace declaration
    // (`xmlns="http://www.w3.org/2000/svg"`), which is required by the
    // SVG spec — strip it from the search before checking for hostile URLs.
    const svgWithoutNs = svg.replace(/xmlns="http:\/\/www\.w3\.org\/[^"]*"/g, "");
    expect(svgWithoutNs).not.toContain("https://");
    expect(svgWithoutNs).not.toContain("http://");
    expect(svg).not.toContain("<script");
  });

  it("renders a branded credential across all built-in schemas", () => {
    handleBrandingSet({
      primaryColor: "#1d4ed8",
      accentColor: "#f59e0b",
      logoFile: { mimeType: "image/png", base64: TINY_PNG_BASE64 },
    });
    const branding = getActiveBranding();

    const schemaIds = ["education", "employment", "identity", "health", "business", "default"];
    for (const schemaId of schemaIds) {
      const svg = renderCredentialSvg(BRANDED_CREDENTIAL, schemaId, { branding });
      expect(svg).toContain("#1d4ed8");
      expect(svg).toContain("#f59e0b");
      expect(svg).toMatch(/data:image\/png;base64,/);
    }
  });

  it("falls back to OpenCred defaults after clear()", () => {
    handleBrandingSet({ primaryColor: "#fa8072", accentColor: "#9333ea" });
    expect(getActiveBranding()).toBeDefined();

    handleBrandingClear();
    expect(getActiveBranding()).toBeUndefined();

    const svg = renderCredentialSvg(BRANDED_CREDENTIAL, "education", undefined);
    expect(svg).toContain("#1a56db");
    expect(svg).toContain("#0ea5e9");
  });

  it("strips PNG metadata before rendering", () => {
    // Build a PNG with a tEXt chunk
    const basePng = Buffer.from(TINY_PNG_BASE64, "base64");
    const iendOffset = basePng.length - 12;
    const beforeIend = basePng.subarray(0, iendOffset);
    const iendChunk = basePng.subarray(iendOffset);
    const data = Buffer.from("Comment\0LEAKY-METADATA-MARKER", "ascii");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length, 0);
    const type = Buffer.from("tEXt", "ascii");
    const crc = Buffer.alloc(4);
    const polluted = Buffer.concat([beforeIend, length, type, data, crc, iendChunk]);

    handleBrandingSet({
      logoFile: { mimeType: "image/png", base64: polluted.toString("base64") },
    });
    const branding = getActiveBranding();

    const svg = renderCredentialSvg(BRANDED_CREDENTIAL, "education", { branding });

    // The metadata marker must NOT appear in the rendered SVG
    expect(svg).not.toContain("LEAKY-METADATA-MARKER");
    // The logo IS embedded
    expect(svg).toMatch(/data:image\/png;base64,/);
  });

  it("rejects a hostile SVG logo and never embeds the script", () => {
    const hostile =
      '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("xss")</script><rect width="10" height="10" fill="red"/></svg>';
    const result = handleBrandingSet({
      logoFile: { mimeType: "image/svg+xml", base64: Buffer.from(hostile, "utf8").toString("base64") },
    });
    expect(result.success).toBe(true);

    const branding = getActiveBranding();
    const svg = renderCredentialSvg(BRANDED_CREDENTIAL, "education", { branding });

    // Script never reaches the rendered output
    expect(svg).not.toContain("<script");
    expect(svg).not.toContain("alert");
    expect(svg).not.toContain("xss");
    // The benign rect part is preserved (after sanitization + base64 + decode)
    expect(svg).toMatch(/data:image\/svg\+xml;base64,/);
  });
});
