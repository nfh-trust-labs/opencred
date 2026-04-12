import { describe, it, expect } from "vitest";
import { createRegistry, Validator } from "../index.js";
import { educationV1Definition, educationV1Schema } from "../schemas/education-v1.js";

describe("Education schema (v1)", () => {
  it("has the expected ID and version", () => {
    expect(educationV1Definition.id).toBe("education/v1");
    expect(educationV1Definition.version).toBe("1.0.0");
  });

  it("follows the W3C VC 2.0 envelope pattern", () => {
    const props = educationV1Schema["properties"] as Record<string, unknown>;
    expect(props).toBeDefined();
    expect(props["@context"]).toBeDefined();
    expect(props["id"]).toBeDefined();
    expect(props["type"]).toBeDefined();
    expect(props["issuer"]).toBeDefined();
    expect(props["validFrom"]).toBeDefined();
    expect(props["credentialSubject"]).toBeDefined();

    const required = educationV1Schema["required"] as string[];
    expect(required).toContain("@context");
    expect(required).toContain("credentialSubject");
  });

  it("has a $schema field", () => {
    expect(educationV1Schema["$schema"]).toBe(
      "https://json-schema.org/draft/2020-12/schema",
    );
  });

  it("defines the expected credentialSubject fields in $defs", () => {
    const defs = educationV1Schema["$defs"] as Record<string, Record<string, unknown>>;
    const subject = defs["EducationSubject"];
    expect(subject).toBeDefined();

    const subjectRequired = subject["required"] as string[];
    expect(subjectRequired).toEqual([
      "recipientName",
      "degree",
      "institution",
      "dateConferred",
    ]);

    const subjectProps = subject["properties"] as Record<string, unknown>;
    expect(subjectProps["recipientName"]).toBeDefined();
    expect(subjectProps["degree"]).toBeDefined();
    expect(subjectProps["institution"]).toBeDefined();
    expect(subjectProps["dateConferred"]).toBeDefined();
    expect(subjectProps["fieldOfStudy"]).toBeDefined();
    expect(subjectProps["honours"]).toBeDefined();
    expect(subjectProps["gpa"]).toBeDefined();
    expect(subjectProps["accreditationBody"]).toBeDefined();
    expect(subjectProps["programDuration"]).toBeDefined();
    expect(subjectProps["credentialNumber"]).toBeDefined();
  });

  it("has a valid checksum (SHA-256 hex)", () => {
    expect(educationV1Definition.checksum).toMatch(/^[0-9a-f]{64}$/);
  });

  it("has source provenance", () => {
    expect(educationV1Definition.source.kind).toBe("defined");
    expect(educationV1Definition.source.upstreamOwner).toBe("OpenCred");
  });

  it("is registered in the default registry", () => {
    const registry = createRegistry();
    const ids = registry.listSchemas();
    expect(ids).toContain("education/v1");

    const def = registry.getSchema("education/v1");
    expect(def.id).toBe("education/v1");
    expect(def.category).toBe("education");
  });

  it("validates a valid credential subject", () => {
    const registry = createRegistry();
    const validator = new Validator(registry);
    const result = validator.validateCredentialSubject("education/v1", {
      recipientName: "Jane Doe",
      degree: "Bachelor of Science",
      institution: "Example University",
      dateConferred: "2025-06-15",
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("validates a credential subject with optional fields", () => {
    const registry = createRegistry();
    const validator = new Validator(registry);
    const result = validator.validateCredentialSubject("education/v1", {
      recipientName: "Jane Doe",
      degree: "Bachelor of Science",
      institution: "Example University",
      dateConferred: "2025-06-15",
      fieldOfStudy: "Computer Science",
      honours: "summa cum laude",
      gpa: 3.95,
      accreditationBody: "ABET",
      programDuration: "4 years",
      credentialNumber: "EDU-2025-0042",
    });
    expect(result.valid).toBe(true);
  });

  it("rejects a credential subject missing required fields", () => {
    const registry = createRegistry();
    const validator = new Validator(registry);
    const result = validator.validateCredentialSubject("education/v1", {
      recipientName: "Jane Doe",
      // missing degree, institution, dateConferred
    });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("rejects an invalid gpa type", () => {
    const registry = createRegistry();
    const validator = new Validator(registry);
    const result = validator.validateCredentialSubject("education/v1", {
      recipientName: "Jane Doe",
      degree: "BSc",
      institution: "University",
      dateConferred: "2025-06-15",
      gpa: "not-a-number",
    });
    expect(result.valid).toBe(false);
  });
});
