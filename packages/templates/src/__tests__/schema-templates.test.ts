import { describe, it, expect } from "vitest";
import { getTemplate, listTemplateIds, renderSvg } from "../index.js";
import type { RenderOptions } from "../types.js";

/**
 * v1 templates package: every schema uses the default template.
 * Schema-specific branded templates are a v1.1 follow-up.
 *
 * These tests verify the v1 behaviour:
 *   - Default template is registered
 *   - Unknown schema IDs fall back to default
 *   - Category IDs (e.g. "traceability/*") fall back to default (for now;
 *     populated in v1.1 when category templates land)
 *   - Rendering + customization + XML escaping still work against default
 */

const SAMPLE_SCHEMA_IDS = [
  "immunization/v1",
  "prescription/v1",
  "test-result/v1",
  "employment-offer-letter/v1",
  "business-entity/v1",
  "electricity/v1",
  "salary-slip/v1",
  "open-badges/v3",
  "dif/verified-person/v1",
  "dif/proof-of-age/v1",
  "traceability/commercial-invoice/v1",
  "traceability/bill-of-lading/v1",
  "insurance-policy/v1",
  "functional-identity/v1",
] as const;

function makeRenderOptions(overrides?: Partial<RenderOptions>): RenderOptions {
  return {
    values: {
      issuerName: "Test Issuer",
      credentialTitle: "Sample Credential",
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2027-01-01T00:00:00Z",
      subject: {
        name: "Jane Doe",
        id: "did:example:subject",
      },
      ...overrides?.values,
    },
    customization: overrides?.customization,
  };
}

// ─────────────────────────────────────────────────────────────
// 1. Template registration
// ─────────────────────────────────────────────────────────────

describe("schema template registration (v1)", () => {
  it("registers the default template", () => {
    expect(listTemplateIds()).toContain("default");
  });

  it("lists exactly 1 template in v1 (default only)", () => {
    expect(listTemplateIds()).toHaveLength(1);
  });

  it.each(SAMPLE_SCHEMA_IDS)(
    "falls back to default for %s (v1.1 will add branded templates)",
    (schemaId) => {
      const template = getTemplate(schemaId);
      expect(template.id).toBe("default");
    },
  );

  it("falls back to default for unknown schema IDs", () => {
    const template = getTemplate("nonexistent-schema/v1");
    expect(template.id).toBe("default");
  });

  it("falls back to default when schemaId is undefined", () => {
    const template = getTemplate(undefined);
    expect(template.id).toBe("default");
  });

  it("falls back to default for category-prefixed IDs (traceability/*)", () => {
    const template = getTemplate("traceability/commercial-invoice/v1");
    expect(template.id).toBe("default");
  });

  it("falls back to default for category-prefixed IDs (dif/*)", () => {
    const template = getTemplate("dif/verified-person/v1");
    expect(template.id).toBe("default");
  });
});

// ─────────────────────────────────────────────────────────────
// 2. Default template rendering
// ─────────────────────────────────────────────────────────────

describe("default template rendering", () => {
  it("renders generic subject fields (name, id)", () => {
    const template = getTemplate("immunization/v1");
    const options = makeRenderOptions();
    const rendered = renderSvg(template.svg, options);

    expect(rendered).toContain("Jane Doe");
    expect(rendered).toContain("did:example:subject");
  });

  it("renders issuerName and credentialTitle", () => {
    const template = getTemplate();
    const options = makeRenderOptions();
    const rendered = renderSvg(template.svg, options);

    expect(rendered).toContain("Test Issuer");
    expect(rendered).toContain("Sample Credential");
  });

  it("renders validFrom and validUntil as formatted dates", () => {
    const template = getTemplate();
    const options = makeRenderOptions();
    const rendered = renderSvg(template.svg, options);

    expect(rendered).toContain("January");
    expect(rendered).toContain("2026");
    expect(rendered).toContain("2027");
  });

  it("handles missing validUntil gracefully", () => {
    const template = getTemplate();
    const options = makeRenderOptions();
    delete options.values.validUntil;
    const rendered = renderSvg(template.svg, options);

    expect(rendered).toContain("Jane Doe");
    expect(rendered).toContain("No expiry");
  });

  it("renders QR code when provided", () => {
    const template = getTemplate();
    const options = makeRenderOptions({
      values: {
        issuerName: "Test Issuer",
        credentialTitle: "Sample Credential",
        validFrom: "2026-01-01T00:00:00Z",
        subject: { name: "Jane Doe", id: "did:example:subject" },
        qrCode: "data:image/png;base64,testqr",
      },
    });
    const rendered = renderSvg(template.svg, options);

    expect(rendered).toContain("data:image/png;base64,testqr");
  });

  it("omits QR code section when not provided", () => {
    const template = getTemplate();
    const options = makeRenderOptions();
    const rendered = renderSvg(template.svg, options);

    expect(rendered).not.toContain("data:image/png");
  });
});

// ─────────────────────────────────────────────────────────────
// 3. Template customization
// ─────────────────────────────────────────────────────────────

describe("template customization", () => {
  it("applies custom primaryColor", () => {
    const template = getTemplate();
    const options = makeRenderOptions({
      customization: { primaryColor: "#ff00ff" },
    });
    const rendered = renderSvg(template.svg, options);

    expect(rendered).toContain("#ff00ff");
  });

  it("applies logoDataUri", () => {
    const template = getTemplate();
    const options = makeRenderOptions({
      customization: { logoDataUri: "data:image/png;base64,logo456" },
    });
    const rendered = renderSvg(template.svg, options);

    expect(rendered).toContain("data:image/png;base64,logo456");
  });

  it("applies issuerDisplayName", () => {
    const template = getTemplate();
    const options = makeRenderOptions({
      customization: { issuerDisplayName: "Custom Org Display" },
    });
    const rendered = renderSvg(template.svg, options);

    expect(rendered).toContain("Custom Org Display");
    expect(rendered).not.toContain("Test Issuer");
  });

  it("omits logo section when logoDataUri is absent", () => {
    const template = getTemplate();
    const options = makeRenderOptions();
    const rendered = renderSvg(template.svg, options);

    expect(rendered).not.toContain("{{logoDataUri}}");
  });
});

// ─────────────────────────────────────────────────────────────
// 4. Template SVG structure
// ─────────────────────────────────────────────────────────────

describe("default template SVG structure", () => {
  it("is valid SVG with consistent viewport", () => {
    const template = getTemplate();
    expect(template.svg).toContain('viewBox="0 0 800 560"');
    expect(template.svg).toContain('width="800"');
    expect(template.svg).toContain('height="560"');
    expect(template.svg).toContain("<svg");
    expect(template.svg).toContain("</svg>");
  });

  it("contains required placeholders", () => {
    const template = getTemplate();
    expect(template.svg).toContain("{{primaryColor}}");
    expect(template.svg).toContain("{{credentialTitle}}");
    expect(template.svg).toContain("{{issuerName}}");
    expect(template.svg).toContain("{{validFrom}}");
  });

  it("has QR code conditional section", () => {
    const template = getTemplate();
    expect(template.svg).toContain("{{#qrCode}}");
    expect(template.svg).toContain("{{/qrCode}}");
  });

  it("has logo conditional section", () => {
    const template = getTemplate();
    expect(template.svg).toContain("{{#logoDataUri}}");
    expect(template.svg).toContain("{{/logoDataUri}}");
  });
});

// ─────────────────────────────────────────────────────────────
// 5. XML safety
// ─────────────────────────────────────────────────────────────

describe("XML escaping", () => {
  it("escapes special characters in subject values", () => {
    const template = getTemplate();
    const options = makeRenderOptions();
    options.values.subject.name = 'O\'Brien & "Friends" <Team>';

    const rendered = renderSvg(template.svg, options);

    expect(rendered).toContain("O&apos;Brien &amp; &quot;Friends&quot; &lt;Team&gt;");
    expect(rendered).not.toContain("<Team>");
  });
});
