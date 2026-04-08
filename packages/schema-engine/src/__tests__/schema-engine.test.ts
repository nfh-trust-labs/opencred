import { describe, it, expect, beforeEach } from "vitest";
import { SchemaValidationError, NotFoundError } from "@opencred/shared";
import { SchemaRegistry } from "../schema-registry.js";
import { Validator } from "../validator.js";
import { createRegistry } from "../index.js";

describe("SchemaRegistry", () => {
  let registry: SchemaRegistry;

  beforeEach(() => {
    registry = new SchemaRegistry();
  });

  it("registers and retrieves a schema", () => {
    const schema = { type: "object", properties: { name: { type: "string" } } };
    registry.registerSchema("test", schema);
    const result = registry.getSchema("test");
    expect(result.id).toBe("test");
    expect(result.schema).toBe(schema);
  });

  it("throws NotFoundError for unknown schema", () => {
    expect(() => registry.getSchema("unknown")).toThrow(NotFoundError);
  });

  it("lists all registered schema IDs", () => {
    registry.registerSchema("a", { type: "object" });
    registry.registerSchema("b", { type: "object" });
    registry.registerSchema("c", { type: "object" });
    expect(registry.listSchemas()).toEqual(["a", "b", "c"]);
  });

  it("maps type to context URL", () => {
    registry.registerSchema("education", { type: "object" }, "https://example.com/education/v1");
    expect(registry.getContextForType("education")).toBe("https://example.com/education/v1");
  });

  it("returns undefined for unmapped type", () => {
    expect(registry.getContextForType("unknown")).toBeUndefined();
  });
});

describe("createRegistry", () => {
  it("auto-registers all built-in schemas", () => {
    const registry = createRegistry();
    const ids = registry.listSchemas();
    expect(ids).toContain("education");
    expect(ids).toContain("employment");
    expect(ids).toContain("identity");
    expect(ids).toContain("health");
    expect(ids).toContain("business");
    expect(ids).toHaveLength(5);
  });

  it("maps built-in types to context URLs", () => {
    const registry = createRegistry();
    expect(registry.getContextForType("education")).toBe(
      "https://schema.nfh.global/contexts/education/v1",
    );
    expect(registry.getContextForType("employment")).toBe(
      "https://schema.nfh.global/contexts/employment/v1",
    );
    expect(registry.getContextForType("identity")).toBe(
      "https://schema.nfh.global/contexts/identity/v1",
    );
    expect(registry.getContextForType("health")).toBe(
      "https://schema.nfh.global/contexts/health/v1",
    );
    expect(registry.getContextForType("business")).toBe(
      "https://schema.nfh.global/contexts/business/v1",
    );
  });
});

describe("Validator", () => {
  let validator: Validator;

  beforeEach(() => {
    const registry = createRegistry();
    validator = new Validator(registry);
  });

  describe("education schema", () => {
    it("accepts valid education credential", () => {
      const result = validator.validateCredentialSubject("education", {
        name: "Jane Doe",
        degree: "Bachelor of Science",
        institution: "MIT",
        dateConferred: "2023-06-15",
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it("rejects missing required fields", () => {
      const result = validator.validateCredentialSubject("education", {
        name: "Jane Doe",
      });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      const fields = result.errors.map((e) => e.field);
      expect(fields).toContain("degree");
      expect(fields).toContain("institution");
      expect(fields).toContain("dateConferred");
    });

    it("rejects invalid date format", () => {
      const result = validator.validateCredentialSubject("education", {
        name: "Jane Doe",
        degree: "BSc",
        institution: "MIT",
        dateConferred: "not-a-date",
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.field === "dateConferred")).toBe(true);
    });
  });

  describe("employment schema", () => {
    it("accepts valid employment credential", () => {
      const result = validator.validateCredentialSubject("employment", {
        name: "John Smith",
        employer: "Acme Corp",
        position: "Engineer",
        startDate: "2022-01-01",
      });
      expect(result.valid).toBe(true);
    });

    it("rejects empty strings for required fields", () => {
      const result = validator.validateCredentialSubject("employment", {
        name: "",
        employer: "Acme",
        position: "Dev",
        startDate: "2022-01-01",
      });
      expect(result.valid).toBe(false);
    });
  });

  describe("identity schema", () => {
    it("accepts valid identity credential", () => {
      const result = validator.validateCredentialSubject("identity", {
        name: "Alice",
        dateOfBirth: "1990-05-20",
        nationality: "Canadian",
        documentNumber: "AB123456",
      });
      expect(result.valid).toBe(true);
    });

    it("rejects wrong types", () => {
      const result = validator.validateCredentialSubject("identity", {
        name: 123,
        dateOfBirth: "1990-05-20",
        nationality: "Canadian",
        documentNumber: "AB123456",
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.field === "name")).toBe(true);
    });
  });

  describe("health schema", () => {
    it("accepts valid health credential", () => {
      // `validUntil` lives on the VC itself (not the subject) — the
      // certification expiry IS the credential expiry, so the subject schema
      // intentionally has no `validUntil` property.
      const result = validator.validateCredentialSubject("health", {
        name: "Bob",
        certification: "First Aid",
        issuingBody: "Red Cross",
      });
      expect(result.valid).toBe(true);
    });

    it("rejects missing required fields", () => {
      const result = validator.validateCredentialSubject("health", {});
      expect(result.valid).toBe(false);
      // Three required fields remain after dropping the subject-level
      // `validUntil`: name, certification, issuingBody.
      expect(result.errors.length).toBe(3);
    });

    it("does not require subject-level validUntil", () => {
      // Regression: the subject-level `validUntil` was removed because it
      // semantically collides with the W3C credentials-v2 VC-level
      // `validUntil`.  Subjects without it must validate.
      const result = validator.validateCredentialSubject("health", {
        name: "Bob",
        certification: "First Aid",
        issuingBody: "Red Cross",
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it("ignores subject-level validUntil if a caller still includes it", () => {
      // `additionalProperties: true` means stale callers that pass a
      // subject-level `validUntil` still validate — they are simply not
      // required, and the field is treated as an additional property.
      const result = validator.validateCredentialSubject("health", {
        name: "Bob",
        certification: "First Aid",
        issuingBody: "Red Cross",
        validUntil: "2025-12-31",
      });
      expect(result.valid).toBe(true);
    });
  });

  describe("business schema", () => {
    it("accepts valid business credential", () => {
      const result = validator.validateCredentialSubject("business", {
        name: "Acme Inc",
        registrationNumber: "REG-12345",
        jurisdiction: "Delaware",
        incorporationDate: "2020-03-01",
      });
      expect(result.valid).toBe(true);
    });

    it("rejects invalid incorporation date", () => {
      const result = validator.validateCredentialSubject("business", {
        name: "Acme Inc",
        registrationNumber: "REG-12345",
        jurisdiction: "Delaware",
        incorporationDate: "invalid",
      });
      expect(result.valid).toBe(false);
    });
  });

  describe("custom schema", () => {
    it("validates against a custom registered schema", () => {
      const registry = new SchemaRegistry();
      registry.registerSchema("custom", {
        type: "object",
        required: ["foo"],
        properties: {
          foo: { type: "number" },
        },
        additionalProperties: false,
      });
      const customValidator = new Validator(registry);

      expect(customValidator.validateCredentialSubject("custom", { foo: 42 }).valid).toBe(true);
      expect(
        customValidator.validateCredentialSubject("custom", { foo: "not-a-number" }).valid,
      ).toBe(false);
      expect(customValidator.validateCredentialSubject("custom", {}).valid).toBe(false);
    });
  });

  describe("validateOrThrow", () => {
    it("does not throw for valid data", () => {
      expect(() =>
        validator.validateOrThrow("education", {
          name: "Jane",
          degree: "PhD",
          institution: "Stanford",
          dateConferred: "2024-01-15",
        }),
      ).not.toThrow();
    });

    it("throws SchemaValidationError for invalid data", () => {
      expect(() => validator.validateOrThrow("education", {})).toThrow(SchemaValidationError);
    });
  });

  describe("error messages", () => {
    it("provides clear field paths in errors", () => {
      const result = validator.validateCredentialSubject("education", {
        name: "Jane",
        degree: "BSc",
        institution: "MIT",
        dateConferred: "bad-date",
      });
      expect(result.valid).toBe(false);
      const dateError = result.errors.find((e) => e.field === "dateConferred");
      expect(dateError).toBeDefined();
      expect(dateError!.message).toBeTruthy();
    });
  });
});
