import { describe, it, expect } from "vitest";
import { renderSvg } from "../renderer.js";
import type { RenderOptions } from "../types.js";

const SIMPLE_TEMPLATE = `<svg>
  <text>{{issuerName}}</text>
  <text>{{credentialTitle}}</text>
  <text>{{validFrom}}</text>
  <text>{{validUntil}}</text>
  <text>{{subject.name}}</text>
  <text>{{subject.id}}</text>
  <rect fill="{{primaryColor}}" />
</svg>`;

const CONDITIONAL_TEMPLATE = `<svg>
  {{#qrCode}}<image href="{{qrCode}}" />{{/qrCode}}
  {{#logoDataUri}}<image href="{{logoDataUri}}" />{{/logoDataUri}}
</svg>`;

function defaultOptions(): RenderOptions {
  return {
    values: {
      issuerName: "Example University",
      credentialTitle: "Education Credential",
      validFrom: "2026-01-15T00:00:00Z",
      validUntil: "2027-01-15T00:00:00Z",
      subject: {
        name: "Jane Doe",
        id: "did:key:z6MkStudent",
      },
    },
  };
}

describe("renderSvg", () => {
  it("substitutes all basic placeholders", () => {
    const result = renderSvg(SIMPLE_TEMPLATE, defaultOptions());

    expect(result).toContain("Example University");
    expect(result).toContain("Education Credential");
    expect(result).toContain("Jane Doe");
    expect(result).toContain("did:key:z6MkStudent");
  });

  it("formats date placeholders as human-readable", () => {
    const result = renderSvg(SIMPLE_TEMPLATE, defaultOptions());

    // Should contain formatted date, not raw ISO
    expect(result).toContain("January");
    expect(result).toContain("2026");
    expect(result).not.toContain("2026-01-15T00:00:00Z");
  });

  it("shows 'No expiry' when validUntil is missing", () => {
    const options = defaultOptions();
    delete options.values.validUntil;

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain("No expiry");
  });

  it("applies default primary color when no customization", () => {
    const result = renderSvg(SIMPLE_TEMPLATE, defaultOptions());

    expect(result).toContain("#1a56db");
  });

  it("applies custom primary color", () => {
    const options = defaultOptions();
    options.customization = { primaryColor: "#ff5733" };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain("#ff5733");
    expect(result).not.toContain("#1a56db");
  });

  it("overrides issuerName with issuerDisplayName", () => {
    const options = defaultOptions();
    options.customization = { issuerDisplayName: "Custom University Name" };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain("Custom University Name");
    expect(result).not.toContain("Example University");
  });

  it("renders conditional section when value exists", () => {
    const options = defaultOptions();
    options.values.qrCode = "data:image/png;base64,abc";

    const result = renderSvg(CONDITIONAL_TEMPLATE, options);

    expect(result).toContain('<image href="data:image/png;base64,abc" />');
  });

  it("removes conditional section when value is missing", () => {
    const options = defaultOptions();
    // No qrCode, no logoDataUri

    const result = renderSvg(CONDITIONAL_TEMPLATE, options);

    expect(result).not.toContain("<image");
  });

  it("renders logo when logoDataUri customization provided", () => {
    const options = defaultOptions();
    options.customization = { logoDataUri: "data:image/png;base64,logo123" };

    const result = renderSvg(CONDITIONAL_TEMPLATE, options);

    expect(result).toContain("data:image/png;base64,logo123");
  });

  it("escapes XML special characters in subject values", () => {
    const options = defaultOptions();
    options.values.subject.name = 'O\'Brien & "Friends" <Team>';

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain("O&apos;Brien &amp; &quot;Friends&quot; &lt;Team&gt;");
    expect(result).not.toContain("<Team>");
  });

  it("replaces missing placeholders with empty string", () => {
    const template = "<svg>{{nonexistent}}</svg>";
    const result = renderSvg(template, defaultOptions());

    expect(result).toBe("<svg></svg>");
  });

  it("handles empty subject", () => {
    const options = defaultOptions();
    options.values.subject = {};

    const template = "<svg>{{subject.name}}</svg>";
    const result = renderSvg(template, options);

    expect(result).toBe("<svg></svg>");
  });
});
