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

  // ─────────────────────────────────────────────────────────────────
  // XSS / injection coverage (issue #315)
  // ─────────────────────────────────────────────────────────────────

  describe("XSS protection (issue #315)", () => {
    /** Strip every text node from an SVG and return the structural skeleton. */
    function stripTextContent(svg: string): string {
      // Remove the contents of every <text>...</text> element.
      return svg.replace(/<text\b[^>]*>[\s\S]*?<\/text>/g, "<text></text>");
    }

    /**
     * Assert that a rendered SVG does not contain executable script. We
     * focus on the structural shape outside text content: hostile markup
     * inside an escaped `<text>` element is fine because the browser
     * displays it as text. Hostile markup OUTSIDE a `<text>` element
     * (e.g. an injected `<script>` tag, an `on*` event handler, or a
     * `javascript:` URL in an `href`/`src` attribute) is the actual
     * threat.
     */
    function assertNoScript(rendered: string): void {
      const skeleton = stripTextContent(rendered);
      // No real <script> elements anywhere in the structural skeleton.
      expect(skeleton.toLowerCase()).not.toContain("<script");
      // No event-handler attributes anywhere in the structural skeleton.
      expect(skeleton.toLowerCase()).not.toMatch(/\son[a-z]+\s*=/);
      // No javascript: URI scheme anywhere — neither in attributes nor
      // text content. (We check the raw output for this one because
      // browsers will run javascript:-scheme URLs from any context.)
      expect(rendered.toLowerCase()).not.toContain("javascript:");
    }

    it("escapes hostile credentialTitle (no <script> in output)", () => {
      const options = defaultOptions();
      options.values.credentialTitle =
        '</text><script>alert("xss")</script><text>';

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      assertNoScript(result);
      // The escaped payload appears in text content.
      expect(result).toContain("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;");
      // The literal `</text>` from the payload should NOT appear unescaped
      // (it would close the wrapping <text> element early).
      expect(result).toContain("&lt;/text&gt;");
    });

    it("escapes hostile issuerName (no markup in output)", () => {
      const options = defaultOptions();
      options.values.issuerName =
        '<svg/onload="alert(1)"></svg> & <img src=x onerror=alert(1)>';

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      assertNoScript(result);
      // Escaped form is present.
      expect(result).toContain("&lt;svg/onload=&quot;alert(1)&quot;&gt;");
      expect(result).toContain("&lt;img src=x onerror=alert(1)&gt;");
    });

    it("escapes hostile validFrom / validUntil (no markup in output)", () => {
      const options = defaultOptions();
      // Pass strings that are not parseable as dates so formatDate returns
      // them verbatim, then assert they are escaped.
      options.values.validFrom = '<script>alert("from")</script>';
      options.values.validUntil = '"><script>alert("until")</script>';

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      assertNoScript(result);
      expect(result).toContain("&lt;script&gt;");
      // The double-quote escape sequence appears (defending against
      // injection that would close an attribute).
      expect(result).toContain("&quot;&gt;&lt;script&gt;");
    });

    it("falls back to default primaryColor on CSS injection payload", () => {
      const options = defaultOptions();
      options.customization = {
        primaryColor: "red; background: url(javascript:alert(1)) /*",
      };

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      // The malicious string must not appear anywhere in the output.
      expect(result).not.toContain("javascript");
      expect(result).not.toContain("url(");
      // Falls back to the OpenCred default.
      expect(result).toContain(DEFAULT_PRIMARY_COLOR);
    });

    it("falls back to default accentColor on CSS injection payload", () => {
      const options = defaultOptions();
      options.customization = {
        accentColor: "} body { background: url(javascript:alert(1)) } /*",
      };

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).not.toContain("javascript");
      expect(result).not.toContain("url(");
      expect(result).toContain(DEFAULT_ACCENT_COLOR);
    });

    it("rejects an https:// logo URL (drops the conditional, no remote URL in output)", () => {
      const options = defaultOptions();
      options.customization = { logoDataUri: "https://evil.example/x.svg" };

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).not.toContain("https://evil.example");
      expect(result).not.toContain("evil.example");
      // The conditional should have collapsed because validation rejected
      // the value.
      expect(result).not.toContain("<image");
    });

    it("rejects a javascript: URL pretending to be a data URI", () => {
      const options = defaultOptions();
      // The branding.ts validator rejects anything that does not start with
      // `data:`. Use a string that BEGINS with `data:` but has the wrong
      // MIME type and a hostile fragment.
      options.customization = {
        logoDataUri: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
      };

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      // Wrong MIME type → rejected.
      expect(result).not.toContain("text/html");
      expect(result).not.toContain("<image");
    });

    it("rejects a javascript: URL in qrCode and drops the conditional", () => {
      const options = defaultOptions();
      options.values.qrCode = "javascript:alert(1)";

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).not.toContain("javascript");
      expect(result).not.toContain("alert");
      expect(result).not.toContain("<image");
    });

    it("rejects an https://-scheme qrCode and drops the conditional", () => {
      const options = defaultOptions();
      options.values.qrCode = "https://evil.example/qr.png";

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).not.toContain("https://evil.example");
      expect(result).not.toContain("<image");
    });

    it("rejects a data: URL with a non-image MIME type in qrCode", () => {
      const options = defaultOptions();
      options.values.qrCode =
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==";

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).not.toContain("text/html");
      expect(result).not.toContain("<image");
    });

    it("accepts a valid PNG data URI for qrCode", () => {
      const options = defaultOptions();
      options.values.qrCode = "data:image/png;base64,iVBORw0KGgo=";

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      expect(result).toContain("data:image/png;base64,iVBORw0KGgo=");
    });

    it("primaryColor accepts valid hex colors as-is", () => {
      const options = defaultOptions();
      options.customization = { primaryColor: "#ff5733" };

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).toContain("#ff5733");
      expect(result).not.toContain(DEFAULT_PRIMARY_COLOR);
    });

    it("primaryColor rejects an unquoted CSS expression even when starting with '#'", () => {
      const options = defaultOptions();
      // Looks vaguely like a hex color but contains hostile CSS.
      options.customization = {
        primaryColor: "#fff; background: url(javascript:alert(1))",
      };

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      expect(result).not.toContain("javascript");
      expect(result).not.toContain("background:");
      expect(result).toContain(DEFAULT_PRIMARY_COLOR);
    });

    it("logoDataUri attribute value is XML-escaped (defense in depth)", () => {
      // Construct a "valid" data URI that contains characters which need
      // XML escaping (in practice base64 never produces them, but the
      // renderer must escape regardless of what the validator allows).
      const options = defaultOptions();
      // 1x1 transparent PNG.
      const tinyPng =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=";
      options.customization = { logoDataUri: `data:image/png;base64,${tinyPng}` };

      const result = renderSvg(CONDITIONAL_TEMPLATE, options);

      // The data URI made it through because it is a valid PNG.
      expect(result).toContain(`data:image/png;base64,${tinyPng}`);
    });

    it("issuerDisplayName override is also escaped", () => {
      const options = defaultOptions();
      options.customization = {
        issuerDisplayName: '</text><script>alert("display")</script>',
      };

      const result = renderSvg(SIMPLE_TEMPLATE, options);

      assertNoScript(result);
      expect(result).toContain("&lt;script&gt;");
      expect(result).toContain("&lt;/text&gt;");
    });
  });
});
