import { describe, it, expect, beforeEach } from "vitest";
import { SchemaValidationError, NotFoundError } from "@opencred/shared";
import { SchemaRegistry } from "../schema-registry.js";
import { Validator } from "../validator.js";
import { createRegistry } from "../index.js";
import {
  educationSchema,
  employmentSchema,
  identitySchema,
  healthSchema,
  businessSchema,
} from "../schemas/index.js";

// ---------------------------------------------------------------------------
// SchemaRegistry — edge cases
// ---------------------------------------------------------------------------

describe("SchemaRegistry — edge cases", () => {
  let registry: SchemaRegistry;

  beforeEach(() => {
    registry = new SchemaRegistry();
  });

  it("overwrites a schema when re-registered with the same id", () => {
    const schemaV1 = { type: "object", properties: { a: { type: "string" } } };
    const schemaV2 = { type: "object", properties: { b: { type: "number" } } };

    registry.registerSchema("test", schemaV1);
    registry.registerSchema("test", schemaV2);

    const result = registry.getSchema("test");
    expect(result.schema).toBe(schemaV2);
  });

  it("overwrites context URL when re-registered with the same id", () => {
    registry.registerSchema("x", { type: "object" }, "https://v1.example");
    registry.registerSchema("x", { type: "object" }, "https://v2.example");

    expect(registry.getContextForType("x")).toBe("https://v2.example");
  });

  it("stores schema without context URL", () => {
    registry.registerSchema("no-context", { type: "object" });
    const def = registry.getSchema("no-context");
    expect(def.contextUrl).toBeUndefined();
    expect(registry.getContextForType("no-context")).toBeUndefined();
  });

  it("listSchemas returns empty array for empty registry", () => {
    expect(registry.listSchemas()).toEqual([]);
  });

  it("listSchemas preserves registration order", () => {
    registry.registerSchema("z", { type: "object" });
    registry.registerSchema("a", { type: "object" });
    registry.registerSchema("m", { type: "object" });
    expect(registry.listSchemas()).toEqual(["z", "a", "m"]);
  });

  it("throws NotFoundError with descriptive message", () => {
    try {
      registry.getSchema("nonexistent");
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(NotFoundError);
      expect((err as NotFoundError).message).toContain("nonexistent");
    }
  });

  it("getSchema returns a consistent definition object", () => {
    registry.registerSchema("stable", { type: "object" }, "https://stable.example");
    const def1 = registry.getSchema("stable");
    const def2 = registry.getSchema("stable");
    expect(def1).toBe(def2);
    expect(def1.id).toBe("stable");
    expect(def1.contextUrl).toBe("https://stable.example");
  });
});

// ---------------------------------------------------------------------------
// Built-in schemas — structural validation
// ---------------------------------------------------------------------------

describe("Built-in schema definitions", () => {
  it("educationSchema has correct $id and required fields", () => {
    expect(educationSchema.$id).toBe(
      "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/education/v1/schema.json",
    );
    expect(educationSchema.required).toContain("name");
    expect(educationSchema.required).toContain("degree");
    expect(educationSchema.required).toContain("institution");
    expect(educationSchema.required).toContain("dateConferred");
    expect(educationSchema.type).toBe("object");
  });

  it("employmentSchema has correct $id and required fields", () => {
    expect(employmentSchema.$id).toBe(
      "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/employment/v1/schema.json",
    );
    expect(employmentSchema.required).toContain("name");
    expect(employmentSchema.required).toContain("employer");
    expect(employmentSchema.required).toContain("position");
    expect(employmentSchema.required).toContain("startDate");
  });

  it("identitySchema has correct $id and required fields", () => {
    expect(identitySchema.$id).toBe(
      "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/identity/v1/schema.json",
    );
    expect(identitySchema.required).toContain("name");
    expect(identitySchema.required).toContain("dateOfBirth");
    expect(identitySchema.required).toContain("nationality");
    expect(identitySchema.required).toContain("documentNumber");
  });

  it("healthSchema has correct $id and required fields", () => {
    expect(healthSchema.$id).toBe(
      "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/health/v1/schema.json",
    );
    expect(healthSchema.required).toContain("name");
    expect(healthSchema.required).toContain("certification");
    expect(healthSchema.required).toContain("issuingBody");
    // validUntil is intentionally NOT a subject-level field — credential
    // expiry is set at the VC level via top-level validUntil.
    expect(healthSchema.required).not.toContain("validUntil");
  });

  it("businessSchema has correct $id and required fields", () => {
    expect(businessSchema.$id).toBe(
      "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/business/v1/schema.json",
    );
    expect(businessSchema.required).toContain("name");
    expect(businessSchema.required).toContain("registrationNumber");
    expect(businessSchema.required).toContain("jurisdiction");
    expect(businessSchema.required).toContain("incorporationDate");
  });

  it("all built-in schemas allow additional properties", () => {
    expect(educationSchema.additionalProperties).toBe(true);
    expect(employmentSchema.additionalProperties).toBe(true);
    expect(identitySchema.additionalProperties).toBe(true);
    expect(healthSchema.additionalProperties).toBe(true);
    expect(businessSchema.additionalProperties).toBe(true);
  });

  it("all built-in schemas use JSON Schema draft-07", () => {
    const schemas = [
      educationSchema,
      employmentSchema,
      identitySchema,
      healthSchema,
      businessSchema,
    ];
    for (const schema of schemas) {
      expect(schema.$schema).toBe("http://json-schema.org/draft-07/schema#");
    }
  });
});

// ---------------------------------------------------------------------------
// Validator — edge cases and data types
// ---------------------------------------------------------------------------

describe("Validator — edge cases", () => {
  let validator: Validator;

  beforeEach(() => {
    const registry = createRegistry();
    validator = new Validator(registry);
  });

  it("rejects null data", () => {
    const result = validator.validateCredentialSubject("education", null);
    expect(result.valid).toBe(false);
  });

  it("rejects undefined data", () => {
    const result = validator.validateCredentialSubject("education", undefined);
    expect(result.valid).toBe(false);
  });

  it("rejects a string as data", () => {
    const result = validator.validateCredentialSubject("education", "not an object");
    expect(result.valid).toBe(false);
  });

  it("rejects a number as data", () => {
    const result = validator.validateCredentialSubject("education", 42);
    expect(result.valid).toBe(false);
  });

  it("rejects an array as data", () => {
    const result = validator.validateCredentialSubject("education", []);
    expect(result.valid).toBe(false);
  });

  it("rejects a boolean as data", () => {
    const result = validator.validateCredentialSubject("education", true);
    expect(result.valid).toBe(false);
  });

  it("accepts valid data with additional properties", () => {
    const result = validator.validateCredentialSubject("education", {
      name: "Jane Doe",
      degree: "BSc",
      institution: "MIT",
      dateConferred: "2023-06-15",
      extraField: "should be allowed",
      anotherExtra: 42,
    });
    expect(result.valid).toBe(true);
  });

  it("throws NotFoundError for unknown schema in validateCredentialSubject", () => {
    expect(() => validator.validateCredentialSubject("nonexistent", {})).toThrow(NotFoundError);
  });

  it("throws NotFoundError for unknown schema in validateOrThrow", () => {
    expect(() => validator.validateOrThrow("nonexistent", {})).toThrow(NotFoundError);
  });

  it("validates all required fields missing produces errors for each field", () => {
    const result = validator.validateCredentialSubject("identity", {});
    expect(result.valid).toBe(false);
    const fields = result.errors.map((e) => e.field);
    expect(fields).toContain("name");
    expect(fields).toContain("dateOfBirth");
    expect(fields).toContain("nationality");
    expect(fields).toContain("documentNumber");
    expect(result.errors).toHaveLength(4);
  });

  it("validates employment with all empty strings fails", () => {
    const result = validator.validateCredentialSubject("employment", {
      name: "",
      employer: "",
      position: "",
      startDate: "",
    });
    expect(result.valid).toBe(false);
    // minLength: 1 should reject all empty strings
    expect(result.errors.length).toBeGreaterThanOrEqual(4);
  });

  it("validates health credential with all required subject fields", () => {
    // validUntil is no longer a subject-level field for health (moved to VC level).
    // additionalProperties: true means stale callers passing it remain accepted.
    const result = validator.validateCredentialSubject("health", {
      name: "Bob",
      certification: "First Aid",
      issuingBody: "Red Cross",
    });
    expect(result.valid).toBe(true);
  });

  it("validates business with numeric registrationNumber fails type check", () => {
    const result = validator.validateCredentialSubject("business", {
      name: "Acme Inc",
      registrationNumber: 12345,
      jurisdiction: "Delaware",
      incorporationDate: "2020-03-01",
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.field === "registrationNumber")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Validator — validateOrThrow details
// ---------------------------------------------------------------------------

describe("Validator — validateOrThrow details", () => {
  let validator: Validator;

  beforeEach(() => {
    const registry = createRegistry();
    validator = new Validator(registry);
  });

  it("SchemaValidationError includes the schema ID in the message", () => {
    try {
      validator.validateOrThrow("education", {});
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(SchemaValidationError);
      expect((err as SchemaValidationError).message).toContain("education");
    }
  });

  it("SchemaValidationError includes validation errors array", () => {
    try {
      validator.validateOrThrow("education", {});
      expect.fail("should have thrown");
    } catch (err) {
      const sve = err as SchemaValidationError;
      expect(sve.validationErrors).toBeDefined();
      expect(Array.isArray(sve.validationErrors)).toBe(true);
      expect(sve.validationErrors.length).toBeGreaterThan(0);
    }
  });

  it("SchemaValidationError.toJSON includes validation errors", () => {
    try {
      validator.validateOrThrow("education", {});
      expect.fail("should have thrown");
    } catch (err) {
      const json = (err as SchemaValidationError).toJSON();
      expect(json.error.code).toBe("SCHEMA_VALIDATION_ERROR");
      expect(json.error.validationErrors).toBeDefined();
    }
  });

  it("does not throw for valid data across all schemas", () => {
    expect(() =>
      validator.validateOrThrow("education", {
        name: "Jane",
        degree: "PhD",
        institution: "Stanford",
        dateConferred: "2024-01-15",
      }),
    ).not.toThrow();

    expect(() =>
      validator.validateOrThrow("employment", {
        name: "John",
        employer: "Acme",
        position: "Dev",
        startDate: "2022-01-01",
      }),
    ).not.toThrow();

    expect(() =>
      validator.validateOrThrow("identity", {
        name: "Alice",
        dateOfBirth: "1990-05-20",
        nationality: "Canadian",
        documentNumber: "AB123",
      }),
    ).not.toThrow();

    expect(() =>
      validator.validateOrThrow("health", {
        name: "Bob",
        certification: "CPR",
        issuingBody: "Red Cross",
        validUntil: "2025-12-31",
      }),
    ).not.toThrow();

    expect(() =>
      validator.validateOrThrow("business", {
        name: "Corp",
        registrationNumber: "REG-1",
        jurisdiction: "DE",
        incorporationDate: "2020-01-01",
      }),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Validator — custom schemas with strict validation
// ---------------------------------------------------------------------------

describe("Validator — custom schema edge cases", () => {
  it("validates against schema with additionalProperties: false", () => {
    const registry = new SchemaRegistry();
    registry.registerSchema("strict", {
      type: "object",
      required: ["x"],
      properties: { x: { type: "string" } },
      additionalProperties: false,
    });
    const v = new Validator(registry);

    expect(v.validateCredentialSubject("strict", { x: "ok" }).valid).toBe(true);
    expect(v.validateCredentialSubject("strict", { x: "ok", y: 1 }).valid).toBe(false);
  });

  it("validates against schema with nested objects", () => {
    const registry = new SchemaRegistry();
    registry.registerSchema("nested", {
      type: "object",
      required: ["address"],
      properties: {
        address: {
          type: "object",
          required: ["city"],
          properties: {
            city: { type: "string" },
            zip: { type: "string" },
          },
        },
      },
    });
    const v = new Validator(registry);

    expect(v.validateCredentialSubject("nested", { address: { city: "Berlin" } }).valid).toBe(true);
    expect(v.validateCredentialSubject("nested", { address: {} }).valid).toBe(false);
    expect(v.validateCredentialSubject("nested", {}).valid).toBe(false);
  });

  it("validates against schema with array types", () => {
    const registry = new SchemaRegistry();
    registry.registerSchema("with-array", {
      type: "object",
      required: ["tags"],
      properties: {
        tags: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
        },
      },
    });
    const v = new Validator(registry);

    expect(v.validateCredentialSubject("with-array", { tags: ["a", "b"] }).valid).toBe(true);
    expect(v.validateCredentialSubject("with-array", { tags: [] }).valid).toBe(false);
    expect(v.validateCredentialSubject("with-array", { tags: [1, 2] }).valid).toBe(false);
  });

  it("validates against schema with enum", () => {
    const registry = new SchemaRegistry();
    registry.registerSchema("with-enum", {
      type: "object",
      required: ["status"],
      properties: {
        status: { type: "string", enum: ["active", "inactive"] },
      },
    });
    const v = new Validator(registry);

    expect(v.validateCredentialSubject("with-enum", { status: "active" }).valid).toBe(true);
    expect(v.validateCredentialSubject("with-enum", { status: "unknown" }).valid).toBe(false);
  });

  it("validates against schema with pattern", () => {
    const registry = new SchemaRegistry();
    registry.registerSchema("with-pattern", {
      type: "object",
      required: ["code"],
      properties: {
        code: { type: "string", pattern: "^[A-Z]{2}[0-9]{4}$" },
      },
    });
    const v = new Validator(registry);

    expect(v.validateCredentialSubject("with-pattern", { code: "AB1234" }).valid).toBe(true);
    expect(v.validateCredentialSubject("with-pattern", { code: "ab1234" }).valid).toBe(false);
    expect(v.validateCredentialSubject("with-pattern", { code: "ABCD" }).valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// createRegistry — immutability / independence
// ---------------------------------------------------------------------------

describe("createRegistry — multiple instances", () => {
  it("creates independent registry instances", () => {
    const reg1 = createRegistry();
    const reg2 = createRegistry();

    // Both have the same built-in schemas
    expect(reg1.listSchemas()).toEqual(reg2.listSchemas());

    // Modifying one does not affect the other
    reg1.registerSchema("custom", { type: "object" });
    expect(reg1.listSchemas()).toContain("custom");
    expect(reg2.listSchemas()).not.toContain("custom");
  });
});
