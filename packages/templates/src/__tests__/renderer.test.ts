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

  // --- Injection regressions (2026-04-07 security review, HIGH) ---
  // A malicious credential must not be able to produce an SVG that executes
  // script when opened. Every credential-derived or issuer-supplied value is
  // either XML-escaped or allowlisted.

  describe("injection hardening", () => {
    it("escapes XML in issuerName", () => {
      const options = defaultOptions();
      options.values.issuerName = '<script>alert(1)</script><a href="x">';

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).not.toContain("<script>");
      expect(result).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    });

    it("escapes XML in credentialTitle", () => {
      const options = defaultOptions();
      options.values.credentialTitle = '</text><image href="x" onload="alert(1)"/><text>';

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).not.toContain("</text><image");
      expect(result).not.toContain('onload="alert(1)"');
    });

    it("escapes XML in the raw-date fallback of validFrom/validUntil", () => {
      const options = defaultOptions();
      options.values.validFrom = "<script>alert(1)</script>";
      options.values.validUntil = "not-a-date <img>";

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).not.toContain("<script>");
      expect(result).not.toContain("<img>");
    });

    it("escapes XML in issuerDisplayName override", () => {
      const options = defaultOptions();
      options.customization = { issuerDisplayName: "<script>alert(1)</script>" };

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).not.toContain("<script>");
    });

    it("drops javascript: logoDataUri", () => {
      const options = defaultOptions();
      options.customization = { logoDataUri: "javascript:alert(1)" };

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).not.toContain("javascript:");
      expect(result).not.toContain("logoDataUri");
    });

    it("drops remote-URL logoDataUri", () => {
      const options = defaultOptions();
      options.customization = { logoDataUri: "https://evil.example/logo.png" };

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).not.toContain("evil.example");
    });

    it("drops SVG data URIs (nested SVG can carry script)", () => {
      const options = defaultOptions();
      options.customization = {
        logoDataUri: "data:image/svg+xml;base64,PHN2Zz48c2NyaXB0Lz48L3N2Zz4=",
      };

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).not.toContain("svg+xml");
    });

    it("drops data URIs with attribute-breakout characters", () => {
      const options = defaultOptions();
      options.customization = {
        sealDataUri: 'data:image/png;base64,abc" onload="alert(1)',
      };

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).not.toContain("onload");
    });

    it("drops malicious qrCode values", () => {
      const options = defaultOptions();
      options.values.qrCode = "javascript:alert(1)";

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).not.toContain("javascript:");
    });

    it("still renders valid raster data URIs for logo, seal, and qrCode", () => {
      const options = defaultOptions();
      options.values.qrCode = "data:image/png;base64,qr+abc/123=";
      options.customization = {
        logoDataUri: "data:image/jpeg;base64,logo123==",
        sealDataUri: "data:image/webp;base64,seal456",
      };

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).toContain('href="data:image/png;base64,qr+abc/123="');
      expect(result).toContain('href="data:image/jpeg;base64,logo123=="');
      expect(result).toContain('href="data:image/webp;base64,seal456"');
    });

    it("falls back to default on CSS-injection primaryColor", () => {
      const options = defaultOptions();
      options.customization = {
        primaryColor: "#fff; } </style><script>alert(1)</script><style>",
      };

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).not.toContain("<script>");
      expect(result).not.toContain("</style>");
      expect(result).toContain("#1a56db");
    });

    it("falls back to default on url() color values", () => {
      const options = defaultOptions();
      options.customization = { backgroundColor: "url(https://evil.example/x)" };

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).not.toContain("url(");
      expect(result).toContain("#ffffff");
    });

    it("sanitizes every color field independently", () => {
      const options = defaultOptions();
      options.customization = {
        secondaryColor: "expression(alert(1))",
        textColor: "}{ fill: red",
        labelColor: '"><script>x</script>',
      };

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).not.toContain("expression(");
      expect(result).not.toContain("}{");
      expect(result).not.toContain("<script>");
      expect(result).toContain("#2d5986");
      expect(result).toContain("#333333");
      expect(result).toContain("#666666");
    });

    it("accepts safe non-hex color shapes", () => {
      const options = defaultOptions();
      options.customization = {
        primaryColor: "rebeccapurple",
        backgroundColor: "rgb(240, 240, 240)",
        textColor: "rgba(0, 0, 0, 0.8)",
      };

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).toContain("rebeccapurple");
      expect(result).toContain("rgb(240, 240, 240)");
      expect(result).toContain("rgba(0, 0, 0, 0.8)");
    });

    it("replaces non-numeric logo dimensions with defaults", () => {
      const options = defaultOptions();
      options.customization = {
        logoDataUri: "data:image/png;base64,logo123",
        // Simulates a JS caller ignoring the number type
        logoWidth: '10" onload="alert(1)' as unknown as number,
        logoHeight: NaN,
      };

      const result = renderSvg(LOGO_SIZE_TEMPLATE, options);

      expect(result).not.toContain("onload");
      expect(result).toContain('width="50"');
      expect(result).toContain('height="50"');
    });
  });
});
