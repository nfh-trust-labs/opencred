/**
 * Tests for credential template rendering and export.
 *
 * Validates SVG rendering from templates, JSON-LD export, QR code generation,
 * and the multi-format packaging function.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { VerifiableCredential } from "@opencred/vc-core";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const testCredential: VerifiableCredential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:test-123",
  type: ["VerifiableCredential", "EducationCredential"],
  issuer: "did:key:z6MkTest",
  validFrom: "2026-01-01T00:00:00Z",
  validUntil: "2027-01-01T00:00:00Z",
  credentialSubject: {
    id: "did:key:z6MkSubject",
    name: "Jane Doe",
    degree: "Bachelor of Science",
    institution: "MIT",
  },
  proof: {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-rdfc-2019",
    created: "2026-01-01T00:00:00Z",
    verificationMethod: "did:key:z6MkTest#z6MkTest",
    proofPurpose: "assertionMethod",
    proofValue: "z3FXQqFhWGuKocnMiM3pyU8gyL3J1vYGjyDz3hXsaHvhP",
  },
};

const testCredentialObjectIssuer: VerifiableCredential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:test-456",
  type: ["VerifiableCredential", "EducationCredential"],
  issuer: { id: "did:key:z6MkTest", name: "Test University" },
  validFrom: "2026-01-01T00:00:00Z",
  credentialSubject: {
    id: "did:key:z6MkSubject",
    name: "John Smith",
    degree: "Master of Arts",
  },
  proof: {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-rdfc-2019",
    created: "2026-01-01T00:00:00Z",
    verificationMethod: "did:key:z6MkTest#z6MkTest",
    proofPurpose: "assertionMethod",
    proofValue: "z3FXQqFhWGuKocnMiM3pyU8gyL3J1vYGjyDz3hXsaHvhP",
  },
};

const testCredentialObjectIssuerNoName: VerifiableCredential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:test-789",
  type: ["VerifiableCredential", "EmploymentCredential"],
  issuer: { id: "did:key:z6MkIssuerNoName" },
  validFrom: "2026-03-01T00:00:00Z",
  credentialSubject: {
    id: "did:key:z6MkEmployee",
    name: "Alice Worker",
  },
  proof: {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-rdfc-2019",
    created: "2026-03-01T00:00:00Z",
    verificationMethod: "did:key:z6MkIssuerNoName#z6MkIssuerNoName",
    proofPurpose: "assertionMethod",
    proofValue: "z3FXQqFhWGuKocnMiM3pyU8gyL3J1vYGjyDz3hXsaHvhP",
  },
};

const testCredentialOnlyVC: VerifiableCredential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:test-only-vc",
  type: ["VerifiableCredential"],
  issuer: "did:key:z6MkMinimal",
  validFrom: "2026-01-01T00:00:00Z",
  credentialSubject: {
    name: "Minimal Subject",
  },
  proof: {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-rdfc-2019",
    created: "2026-01-01T00:00:00Z",
    verificationMethod: "did:key:z6MkMinimal#z6MkMinimal",
    proofPurpose: "assertionMethod",
    proofValue: "z3FXQqFhWGuKocnMiM3pyU8gyL3J1vYGjyDz3hXsaHvhP",
  },
};

// ---------------------------------------------------------------------------
// Mock the templates package — we don't want to depend on filesystem SVG
// loading in unit tests.
//
// NOTE: vi.mock is hoisted above all imports and variable declarations.
// All values used inside the factory must be inlined or defined with vi.hoisted().
// ---------------------------------------------------------------------------

const MOCK_SVG = vi.hoisted(
  () => `<svg>
  <text>{{credentialTitle}}</text>
  <text>{{issuerName}}</text>
  <text>{{validFrom}}</text>
  <text>{{validUntil}}</text>
  <text>{{subject.name}}</text>
  <text>{{subject.degree}}</text>
  <text>{{primaryColor}}</text>
</svg>`,
);

vi.mock("@opencred/templates", () => ({
  getTemplate: vi.fn().mockReturnValue({
    id: "default",
    name: "Default Credential",
    svg: MOCK_SVG,
  }),
  renderSvg: vi.fn(
    (
      svgTemplate: string,
      options: { values: Record<string, unknown>; customization?: Record<string, unknown> },
    ) => {
      // Simplified render for testing — replace placeholders
      let result = svgTemplate;
      const values = options.values as Record<string, unknown>;
      result = result.replace("{{credentialTitle}}", String(values.credentialTitle ?? ""));
      result = result.replace("{{issuerName}}", String(values.issuerName ?? ""));
      result = result.replace("{{validFrom}}", String(values.validFrom ?? ""));
      result = result.replace("{{validUntil}}", String(values.validUntil ?? ""));
      const subject = (values.subject ?? {}) as Record<string, string>;
      result = result.replace("{{subject.name}}", String(subject.name ?? ""));
      result = result.replace("{{subject.degree}}", String(subject.degree ?? ""));
      const customization = options.customization ?? {};
      result = result.replace(
        "{{primaryColor}}",
        String((customization as Record<string, unknown>).primaryColor ?? "#1a56db"),
      );
      return result;
    },
  ),
  listTemplateIds: vi.fn().mockReturnValue(["default"]),
}));

// Mock qrcode — avoid actual QR generation in unit tests
vi.mock("qrcode", () => ({
  default: {
    toDataURL: vi.fn().mockResolvedValue("data:image/png;base64,mockQrData"),
  },
}));

// Now import the module under test (after mocks are set up)
import {
  renderCredentialSvg,
  exportAsJsonLd,
  exportAsQrCode,
  packageCredential,
  extractIssuerName,
  extractCredentialTitle,
  extractSubjectFields,
} from "../main/credential-export.js";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("extractIssuerName", () => {
  it("should extract issuer from string issuer", () => {
    const name = extractIssuerName(testCredential);
    expect(name).toBe("did:key:z6MkTest");
  });

  it("should extract issuer name from object issuer with name", () => {
    const name = extractIssuerName(testCredentialObjectIssuer);
    expect(name).toBe("Test University");
  });

  it("should extract issuer id from object issuer without name", () => {
    const name = extractIssuerName(testCredentialObjectIssuerNoName);
    expect(name).toBe("did:key:z6MkIssuerNoName");
  });
});

describe("extractCredentialTitle", () => {
  it("should extract the last non-VerifiableCredential type", () => {
    const title = extractCredentialTitle(testCredential);
    expect(title).toBe("EducationCredential");
  });

  it("should handle type arrays with multiple custom types", () => {
    const cred = {
      ...testCredential,
      type: ["VerifiableCredential", "EducationCredential", "DegreeCredential"],
    };
    const title = extractCredentialTitle(cred as VerifiableCredential);
    expect(title).toBe("DegreeCredential");
  });

  it("should fallback to 'Verifiable Credential' when only VerifiableCredential type", () => {
    const title = extractCredentialTitle(testCredentialOnlyVC);
    expect(title).toBe("Verifiable Credential");
  });
});

describe("extractSubjectFields", () => {
  it("should flatten credentialSubject to string values", () => {
    const fields = extractSubjectFields(testCredential);
    expect(fields.name).toBe("Jane Doe");
    expect(fields.degree).toBe("Bachelor of Science");
    expect(fields.institution).toBe("MIT");
  });

  it("should include id as a string field", () => {
    const fields = extractSubjectFields(testCredential);
    expect(fields.id).toBe("did:key:z6MkSubject");
  });

  it("should handle missing subject fields gracefully", () => {
    const cred: VerifiableCredential = {
      ...testCredential,
      credentialSubject: {},
    };
    const fields = extractSubjectFields(cred);
    expect(Object.keys(fields).length).toBe(0);
  });
});

describe("renderCredentialSvg", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should produce a valid SVG string with credential data substituted", () => {
    const svg = renderCredentialSvg(testCredential, "functional-identity/v1");

    expect(svg).toContain("<svg>");
    expect(svg).toContain("EducationCredential");
    expect(svg).toContain("did:key:z6MkTest");
    expect(svg).toContain("Jane Doe");
  });

  it("should handle missing optional fields gracefully", () => {
    const credNoExpiry: VerifiableCredential = {
      ...testCredential,
      validUntil: undefined,
    };

    const svg = renderCredentialSvg(credNoExpiry, "functional-identity/v1");
    expect(svg).toContain("<svg>");
    // Should not throw, should render without validUntil
    expect(svg).toBeDefined();
  });

  it("should apply customization options", () => {
    const svg = renderCredentialSvg(testCredential, "functional-identity/v1", {
      primaryColor: "#ff0000",
      issuerDisplayName: "Custom University",
    });

    expect(svg).toContain("<svg>");
    // The mock renderSvg uses customization.primaryColor
    expect(svg).toContain("#ff0000");
  });

  it("should use object issuer name when issuer is an object", () => {
    const svg = renderCredentialSvg(testCredentialObjectIssuer, "functional-identity/v1");

    expect(svg).toContain("Test University");
  });
});

describe("exportAsJsonLd", () => {
  it("should return formatted JSON matching the credential", () => {
    const json = exportAsJsonLd(testCredential);

    const parsed = JSON.parse(json);
    expect(parsed["@context"]).toEqual(["https://www.w3.org/ns/credentials/v2"]);
    expect(parsed.id).toBe("urn:uuid:test-123");
    expect(parsed.type).toEqual(["VerifiableCredential", "EducationCredential"]);
    expect(parsed.issuer).toBe("did:key:z6MkTest");
    expect(parsed.proof).toBeDefined();
  });

  it("should produce formatted output with indentation", () => {
    const json = exportAsJsonLd(testCredential);
    expect(json).toContain("\n");
    expect(json).toContain("  ");
  });
});

describe("exportAsQrCode", () => {
  it("should return a PNG data URI", async () => {
    const dataUri = await exportAsQrCode(testCredential);
    expect(dataUri).toMatch(/^data:image\/png;base64,/);
  });
});

describe("packageCredential", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return correct output for ["json-ld"] format', async () => {
    const outputs = await packageCredential(testCredential, "functional-identity/v1", ["json-ld"]);

    expect(outputs.length).toBe(1);
    expect(outputs[0].format).toBe("json-ld");
    expect(outputs[0].mimeType).toBe("application/ld+json");
    expect(outputs[0].suggestedFileName).toMatch(/\.jsonld$/);
    const parsed = JSON.parse(outputs[0].data);
    expect(parsed.id).toBe("urn:uuid:test-123");
  });

  it('should return rendered SVG for ["svg"] format', async () => {
    const outputs = await packageCredential(testCredential, "functional-identity/v1", ["svg"]);

    expect(outputs.length).toBe(1);
    expect(outputs[0].format).toBe("svg");
    expect(outputs[0].mimeType).toBe("image/svg+xml");
    expect(outputs[0].suggestedFileName).toMatch(/\.svg$/);
    expect(outputs[0].data).toContain("<svg>");
  });

  it("should return all outputs for multiple formats", async () => {
    const outputs = await packageCredential(testCredential, "functional-identity/v1", [
      "json-ld",
      "svg",
      "qr",
    ]);

    expect(outputs.length).toBe(3);
    const formats = outputs.map((o) => o.format);
    expect(formats).toContain("json-ld");
    expect(formats).toContain("svg");
    expect(formats).toContain("qr");
  });

  it("should generate suggested file names", async () => {
    const outputs = await packageCredential(testCredential, "functional-identity/v1", [
      "json-ld",
      "svg",
      "qr",
    ]);

    for (const output of outputs) {
      expect(output.suggestedFileName).toBeTruthy();
      expect(output.suggestedFileName.length).toBeGreaterThan(0);
    }
  });

  it("should pass customization to SVG rendering", async () => {
    const outputs = await packageCredential(testCredential, "functional-identity/v1", ["svg"], {
      primaryColor: "#00ff00",
    });

    expect(outputs.length).toBe(1);
    expect(outputs[0].data).toContain("#00ff00");
  });

  it("should handle credential with only VerifiableCredential type in filename", async () => {
    const outputs = await packageCredential(testCredentialOnlyVC, "default", ["json-ld"]);

    expect(outputs.length).toBe(1);
    // Filename should use "credential" as the type slug
    expect(outputs[0].suggestedFileName).toMatch(/^credential-/);
  });
});
