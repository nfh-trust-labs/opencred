import { describe, it, expect } from "vitest";
import { getTemplate, listTemplateIds, renderSvg } from "../index.js";
import type { RenderOptions } from "../types.js";

/**
 * Schema IDs that must have registered templates.
 */
const SCHEMA_IDS = ["education", "employment", "identity", "health", "business"] as const;

/** Per-schema required subject fields and test data. */
const SCHEMA_FIELDS: Record<
  (typeof SCHEMA_IDS)[number],
  { fields: string[]; subject: Record<string, string>; title: string }
> = {
  education: {
    fields: ["name", "degree", "institution", "dateConferred"],
    subject: {
      name: "Jane Doe",
      degree: "Bachelor of Science",
      institution: "MIT",
      dateConferred: "2025-06-15",
    },
    title: "Education Credential",
  },
  employment: {
    fields: ["name", "employer", "position", "startDate"],
    subject: {
      name: "John Smith",
      employer: "Acme Corp",
      position: "Senior Engineer",
      startDate: "2024-03-01",
    },
    title: "Employment Credential",
  },
  identity: {
    fields: ["name", "dateOfBirth", "nationality", "documentNumber"],
    subject: {
      name: "Alice Johnson",
      dateOfBirth: "1990-05-20",
      nationality: "Canadian",
      documentNumber: "AB1234567",
    },
    title: "Identity Credential",
  },
  health: {
    fields: ["name", "certification", "issuingBody", "validUntil"],
    subject: {
      name: "Dr. Bob Lee",
      certification: "Board Certified Internal Medicine",
      issuingBody: "American Board of Internal Medicine",
      validUntil: "2028-12-31",
    },
    title: "Health Credential",
  },
  business: {
    fields: ["name", "registrationNumber", "jurisdiction", "incorporationDate"],
    subject: {
      name: "OpenCred Inc.",
      registrationNumber: "REG-2024-001",
      jurisdiction: "Delaware, USA",
      incorporationDate: "2024-01-10",
    },
    title: "Business Credential",
  },
};

function makeRenderOptions(
  schemaId: (typeof SCHEMA_IDS)[number],
  overrides?: Partial<RenderOptions>,
): RenderOptions {
  const data = SCHEMA_FIELDS[schemaId];
  return {
    values: {
      issuerName: "Test Issuer",
      credentialTitle: data.title,
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2027-01-01T00:00:00Z",
      subject: { ...data.subject },
      ...overrides?.values,
    },
    customization: overrides?.customization,
  };
}

// ─────────────────────────────────────────────────────────────
// 1. Template registration
// ─────────────────────────────────────────────────────────────

describe("schema template registration", () => {
  it("registers a template for every schema ID", () => {
    const ids = listTemplateIds();
    for (const schemaId of SCHEMA_IDS) {
      expect(ids).toContain(schemaId);
    }
  });

  it("still registers the default template", () => {
    expect(listTemplateIds()).toContain("default");
  });

  it("returns a schema-specific template (not default) for each schema ID", () => {
    for (const schemaId of SCHEMA_IDS) {
      const template = getTemplate(schemaId);
      expect(template.id).toBe(schemaId);
      expect(template.svg).toBeTruthy();
      expect(template.svg).not.toBe(getTemplate("default").svg);
    }
  });

  it("falls back to default for unknown schema IDs", () => {
    const template = getTemplate("nonexistent-schema");
    expect(template.id).toBe("default");
  });

  it("falls back to default when schemaId is undefined", () => {
    const template = getTemplate(undefined);
    expect(template.id).toBe("default");
  });

  it("lists exactly 6 templates (default + 5 schemas)", () => {
    expect(listTemplateIds()).toHaveLength(6);
  });
});

// ─────────────────────────────────────────────────────────────
// 2. Per-schema rendering with required fields
// ─────────────────────────────────────────────────────────────

describe("schema template rendering", () => {
  for (const schemaId of SCHEMA_IDS) {
    describe(schemaId, () => {
      it("renders all required subject fields", () => {
        const template = getTemplate(schemaId);
        const options = makeRenderOptions(schemaId);
        const rendered = renderSvg(template.svg, options);

        const data = SCHEMA_FIELDS[schemaId];
        for (const field of data.fields) {
          expect(rendered).toContain(data.subject[field]);
        }
      });

      it("renders issuerName and credentialTitle", () => {
        const template = getTemplate(schemaId);
        const options = makeRenderOptions(schemaId);
        const rendered = renderSvg(template.svg, options);

        expect(rendered).toContain("Test Issuer");
        expect(rendered).toContain(SCHEMA_FIELDS[schemaId].title);
      });

      it("renders validFrom as formatted date", () => {
        const template = getTemplate(schemaId);
        const options = makeRenderOptions(schemaId);
        const rendered = renderSvg(template.svg, options);

        expect(rendered).toContain("January");
        expect(rendered).toContain("2026");
      });

      it("renders validUntil when provided", () => {
        const template = getTemplate(schemaId);
        const options = makeRenderOptions(schemaId);
        const rendered = renderSvg(template.svg, options);

        expect(rendered).toContain("January");
        expect(rendered).toContain("2027");
      });

      it("handles missing validUntil gracefully", () => {
        const template = getTemplate(schemaId);
        const options = makeRenderOptions(schemaId);
        delete options.values.validUntil;
        const rendered = renderSvg(template.svg, options);

        // Should not crash and should still contain required fields
        const data = SCHEMA_FIELDS[schemaId];
        for (const field of data.fields) {
          expect(rendered).toContain(data.subject[field]);
        }
      });

      it("renders QR code when provided", () => {
        const template = getTemplate(schemaId);
        const options = makeRenderOptions(schemaId, {
          values: {
            issuerName: "Test Issuer",
            credentialTitle: SCHEMA_FIELDS[schemaId].title,
            validFrom: "2026-01-01T00:00:00Z",
            subject: { ...SCHEMA_FIELDS[schemaId].subject },
            qrCode: "data:image/png;base64,testqr",
          },
        });
        const rendered = renderSvg(template.svg, options);

        expect(rendered).toContain("data:image/png;base64,testqr");
      });

      it("omits QR code section when not provided", () => {
        const template = getTemplate(schemaId);
        const options = makeRenderOptions(schemaId);
        // No qrCode in default options
        const rendered = renderSvg(template.svg, options);

        expect(rendered).not.toContain("data:image/png");
      });
    });
  }
});

// ─────────────────────────────────────────────────────────────
// 3. Template customization across all schemas
// ─────────────────────────────────────────────────────────────

describe("template customization", () => {
  for (const schemaId of SCHEMA_IDS) {
    it(`applies custom primaryColor on ${schemaId}`, () => {
      const template = getTemplate(schemaId);
      const options = makeRenderOptions(schemaId, {
        customization: { primaryColor: "#ff00ff" },
      });
      const rendered = renderSvg(template.svg, options);

      expect(rendered).toContain("#ff00ff");
    });

    it(`applies logoDataUri on ${schemaId}`, () => {
      const template = getTemplate(schemaId);
      const options = makeRenderOptions(schemaId, {
        customization: { logoDataUri: "data:image/png;base64,logo456" },
      });
      const rendered = renderSvg(template.svg, options);

      expect(rendered).toContain("data:image/png;base64,logo456");
    });

    it(`applies issuerDisplayName on ${schemaId}`, () => {
      const template = getTemplate(schemaId);
      const options = makeRenderOptions(schemaId, {
        customization: { issuerDisplayName: "Custom Org Display" },
      });
      const rendered = renderSvg(template.svg, options);

      expect(rendered).toContain("Custom Org Display");
      expect(rendered).not.toContain("Test Issuer");
    });

    it(`omits logo section when logoDataUri is absent on ${schemaId}`, () => {
      const template = getTemplate(schemaId);
      const options = makeRenderOptions(schemaId);
      const rendered = renderSvg(template.svg, options);

      // The logoDataUri conditional block should be removed
      expect(rendered).not.toContain("{{logoDataUri}}");
    });
  }
});

// ─────────────────────────────────────────────────────────────
// 4. Template SVG structure
// ─────────────────────────────────────────────────────────────

describe("template SVG structure", () => {
  for (const schemaId of SCHEMA_IDS) {
    it(`${schemaId} template is valid SVG with consistent viewport`, () => {
      const template = getTemplate(schemaId);
      expect(template.svg).toContain('viewBox="0 0 800 560"');
      expect(template.svg).toContain('width="800"');
      expect(template.svg).toContain('height="560"');
      expect(template.svg).toContain("<svg");
      expect(template.svg).toContain("</svg>");
    });

    it(`${schemaId} template contains {{primaryColor}} placeholder`, () => {
      const template = getTemplate(schemaId);
      expect(template.svg).toContain("{{primaryColor}}");
    });

    it(`${schemaId} template contains {{credentialTitle}} placeholder`, () => {
      const template = getTemplate(schemaId);
      expect(template.svg).toContain("{{credentialTitle}}");
    });

    it(`${schemaId} template contains {{issuerName}} placeholder`, () => {
      const template = getTemplate(schemaId);
      expect(template.svg).toContain("{{issuerName}}");
    });

    it(`${schemaId} template contains {{validFrom}} placeholder`, () => {
      const template = getTemplate(schemaId);
      expect(template.svg).toContain("{{validFrom}}");
    });

    it(`${schemaId} template contains subject field placeholders`, () => {
      const template = getTemplate(schemaId);
      const data = SCHEMA_FIELDS[schemaId];
      for (const field of data.fields) {
        expect(template.svg).toContain(`{{subject.${field}}}`);
      }
    });

    it(`${schemaId} template has QR code conditional section`, () => {
      const template = getTemplate(schemaId);
      expect(template.svg).toContain("{{#qrCode}}");
      expect(template.svg).toContain("{{/qrCode}}");
    });

    it(`${schemaId} template has logo conditional section`, () => {
      const template = getTemplate(schemaId);
      expect(template.svg).toContain("{{#logoDataUri}}");
      expect(template.svg).toContain("{{/logoDataUri}}");
    });
  }
});

// ─────────────────────────────────────────────────────────────
// 5. XML safety
// ─────────────────────────────────────────────────────────────

describe("XML escaping in schema templates", () => {
  it("escapes special characters in subject values", () => {
    const template = getTemplate("education");
    const options = makeRenderOptions("education");
    options.values.subject.name = 'O\'Brien & "Friends" <Team>';

    const rendered = renderSvg(template.svg, options);

    expect(rendered).toContain("O&apos;Brien &amp; &quot;Friends&quot; &lt;Team&gt;");
    expect(rendered).not.toContain("<Team>");
  });
});
