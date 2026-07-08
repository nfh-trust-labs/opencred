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
  <rect fill="{{backgroundColor}}" />
  <text fill="{{textColor}}">value</text>
  <text fill="{{labelColor}}">label</text>
  <text fill="{{secondaryColor}}">secondary</text>
  <text>{{footerText}}</text>
</svg>`;

const LOGO_SIZE_TEMPLATE = `<svg>
  {{#logoDataUri}}<image width="{{logoWidth}}" height="{{logoHeight}}" href="{{logoDataUri}}" />{{/logoDataUri}}
</svg>`;

const CONDITIONAL_TEMPLATE = `<svg>
  {{#qrCode}}<image href="{{qrCode}}" />{{/qrCode}}
  {{#logoDataUri}}<image href="{{logoDataUri}}" />{{/logoDataUri}}
  {{#sealDataUri}}<image href="{{sealDataUri}}" />{{/sealDataUri}}
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

  // --- New customization field tests ---

  it("applies default backgroundColor when no customization", () => {
    const result = renderSvg(SIMPLE_TEMPLATE, defaultOptions());

    expect(result).toContain("#ffffff");
  });

  it("applies custom backgroundColor", () => {
    const options = defaultOptions();
    options.customization = { backgroundColor: "#f0f0f0" };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain("#f0f0f0");
  });

  it("applies default textColor when no customization", () => {
    const result = renderSvg(SIMPLE_TEMPLATE, defaultOptions());

    expect(result).toContain('fill="#333333"');
  });

  it("applies custom textColor", () => {
    const options = defaultOptions();
    options.customization = { textColor: "#111111" };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain('fill="#111111"');
  });

  it("applies default labelColor when no customization", () => {
    const result = renderSvg(SIMPLE_TEMPLATE, defaultOptions());

    expect(result).toContain('fill="#666666"');
  });

  it("applies custom labelColor", () => {
    const options = defaultOptions();
    options.customization = { labelColor: "#aaaaaa" };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain('fill="#aaaaaa"');
  });

  it("applies default secondaryColor when no customization", () => {
    const result = renderSvg(SIMPLE_TEMPLATE, defaultOptions());

    expect(result).toContain('fill="#2d5986"');
  });

  it("applies custom secondaryColor", () => {
    const options = defaultOptions();
    options.customization = { secondaryColor: "#445566" };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain('fill="#445566"');
  });

  it("applies default footerText when no customization", () => {
    const result = renderSvg(SIMPLE_TEMPLATE, defaultOptions());

    expect(result).toContain(
      "This credential is digitally signed and can be independently verified.",
    );
    // The default footer must not advertise any OpenCred-flavoured
    // attribution — the same generator runs in the Docker image where
    // the issuer's brand fronts the certificate.
    expect(result).not.toMatch(/OpenCred/);
  });

  it("applies custom footerText", () => {
    const options = defaultOptions();
    options.customization = { footerText: "Custom footer message" };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain("Custom footer message");
    expect(result).not.toContain("This credential is digitally signed");
  });

  it("applies default logo dimensions", () => {
    const options = defaultOptions();
    options.customization = { logoDataUri: "data:image/png;base64,logo123" };

    const result = renderSvg(LOGO_SIZE_TEMPLATE, options);

    expect(result).toContain('width="50"');
    expect(result).toContain('height="50"');
  });

  it("applies custom logo dimensions", () => {
    const options = defaultOptions();
    options.customization = {
      logoDataUri: "data:image/png;base64,logo123",
      logoWidth: 100,
      logoHeight: 80,
    };

    const result = renderSvg(LOGO_SIZE_TEMPLATE, options);

    expect(result).toContain('width="100"');
    expect(result).toContain('height="80"');
  });

  it("renders seal conditional section when sealDataUri provided", () => {
    const options = defaultOptions();
    options.customization = { sealDataUri: "data:image/png;base64,seal456" };

    const result = renderSvg(CONDITIONAL_TEMPLATE, options);

    expect(result).toContain('href="data:image/png;base64,seal456"');
  });

  it("removes seal conditional section when sealDataUri missing", () => {
    const options = defaultOptions();

    const result = renderSvg(CONDITIONAL_TEMPLATE, options);

    expect(result).not.toContain("seal");
  });
});
