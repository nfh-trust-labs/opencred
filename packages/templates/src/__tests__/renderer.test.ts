import { describe, it, expect } from "vitest";
import { renderSvg } from "../renderer.js";
import {
  DEFAULT_ACCENT_COLOR,
  DEFAULT_PRIMARY_COLOR,
  svgToDataUri,
} from "../branding.js";
import type { RenderOptions } from "../types.js";

const SIMPLE_TEMPLATE = `<svg>
  <text>{{issuerName}}</text>
  <text>{{credentialTitle}}</text>
  <text>{{validFrom}}</text>
  <text>{{validUntil}}</text>
  <text>{{subject.name}}</text>
  <text>{{subject.id}}</text>
  <rect fill="{{primaryColor}}" />
  <rect fill="{{accentColor}}" />
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

    expect(result).toContain(DEFAULT_PRIMARY_COLOR);
  });

  it("applies default accent color when no customization", () => {
    const result = renderSvg(SIMPLE_TEMPLATE, defaultOptions());

    expect(result).toContain(DEFAULT_ACCENT_COLOR);
  });

  it("applies custom primary color", () => {
    const options = defaultOptions();
    options.customization = { primaryColor: "#ff5733" };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain("#ff5733");
    expect(result).not.toContain(DEFAULT_PRIMARY_COLOR);
  });

  it("applies custom accent color", () => {
    const options = defaultOptions();
    options.customization = { accentColor: "#22c55e" };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain("#22c55e");
    expect(result).not.toContain(DEFAULT_ACCENT_COLOR);
  });

  it("falls back to defaults for invalid hex colors", () => {
    const options = defaultOptions();
    options.customization = { primaryColor: "javascript:alert(1)", accentColor: "not-a-color" };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain(DEFAULT_PRIMARY_COLOR);
    expect(result).toContain(DEFAULT_ACCENT_COLOR);
    expect(result).not.toContain("javascript:");
  });

  it("applies issuer branding with both primary and accent", () => {
    const options = defaultOptions();
    options.customization = {
      branding: {
        primaryColor: "#fa8072",
        accentColor: "#9333ea",
      },
    };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain("#fa8072");
    expect(result).toContain("#9333ea");
  });

  it("explicit colors override issuer branding", () => {
    const options = defaultOptions();
    options.customization = {
      primaryColor: "#000000",
      branding: {
        primaryColor: "#ffffff",
        accentColor: "#abcdef",
      },
    };

    const result = renderSvg(SIMPLE_TEMPLATE, options);

    expect(result).toContain("#000000"); // explicit override wins for primary
    expect(result).toContain("#abcdef"); // branding wins for accent
    expect(result).not.toContain("#ffffff");
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
    // 1x1 transparent PNG, base64
    const tinyPng =
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=";
    const dataUri = `data:image/png;base64,${tinyPng}`;

    const options = defaultOptions();
    options.customization = { logoDataUri: dataUri };

    const result = renderSvg(CONDITIONAL_TEMPLATE, options);

    expect(result).toContain(dataUri);
  });

  it("renders logo when issuer branding provides logoDataUri", () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="20" height="20" fill="red"/></svg>';
    const dataUri = svgToDataUri(svg);

    const options = defaultOptions();
    options.customization = { branding: { logoDataUri: dataUri } };

    const result = renderSvg(CONDITIONAL_TEMPLATE, options);

    expect(result).toContain(dataUri);
  });

  it("drops a remote URL logo (no http/https in rendered output)", () => {
    const options = defaultOptions();
    options.customization = { logoDataUri: "https://evil.example/logo.png" };

    const result = renderSvg(CONDITIONAL_TEMPLATE, options);

    expect(result).not.toContain("https://evil.example");
    // The conditional should have collapsed because the logo was rejected.
    expect(result).not.toContain("logo.png");
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
