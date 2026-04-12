/**
 * Tests for generateSchemaFromFields — dynamic schema generation from sample data.
 */

import { describe, it, expect } from "vitest";
import { generateSchemaFromFields } from "../schema-generator.js";
import { SchemaRegistry } from "../schema-registry.js";
import { Validator } from "../validator.js";

describe("generateSchemaFromFields", () => {
  // -------------------------------------------------------------------------
  // String inference
  // -------------------------------------------------------------------------

  it("infers plain string", () => {
    const { schema, fields } = generateSchemaFromFields({ name: "Alice" });
    expect((schema.properties as Record<string, unknown>).name).toEqual({ type: "string" });
    expect(fields[0]).toMatchObject({ name: "name", type: "string", required: true });
    expect(fields[0].format).toBeUndefined();
  });

  it("infers email format", () => {
    const { schema, fields } = generateSchemaFromFields({ email: "alice@example.com" });
    expect((schema.properties as Record<string, unknown>).email).toEqual({
      type: "string",
      format: "email",
    });
    expect(fields[0]).toMatchObject({ name: "email", type: "string", format: "email" });
  });

  it("infers URI format", () => {
    const { schema, fields } = generateSchemaFromFields({ website: "https://example.com" });
    expect((schema.properties as Record<string, unknown>).website).toEqual({
      type: "string",
      format: "uri",
    });
    expect(fields[0]).toMatchObject({ name: "website", type: "string", format: "uri" });
  });

  it("infers date format", () => {
    const { schema, fields } = generateSchemaFromFields({ birthDate: "1990-05-15" });
    expect((schema.properties as Record<string, unknown>).birthDate).toEqual({
      type: "string",
      format: "date",
    });
    expect(fields[0]).toMatchObject({ name: "birthDate", type: "string", format: "date" });
  });

  it("infers date-time format", () => {
    const { schema, fields } = generateSchemaFromFields({
      issuedAt: "2024-01-15T10:30:00Z",
    });
    expect((schema.properties as Record<string, unknown>).issuedAt).toEqual({
      type: "string",
      format: "date-time",
    });
    expect(fields[0]).toMatchObject({ name: "issuedAt", type: "string", format: "date-time" });
  });

  // -------------------------------------------------------------------------
  // Number inference
  // -------------------------------------------------------------------------

  it("infers integer type", () => {
    const { schema, fields } = generateSchemaFromFields({ age: 30 });
    expect((schema.properties as Record<string, unknown>).age).toEqual({ type: "integer" });
    expect(fields[0]).toMatchObject({ name: "age", type: "integer" });
  });

  it("infers number type for floats", () => {
    const { schema, fields } = generateSchemaFromFields({ score: 95.5 });
    expect((schema.properties as Record<string, unknown>).score).toEqual({ type: "number" });
    expect(fields[0]).toMatchObject({ name: "score", type: "number" });
  });

  // -------------------------------------------------------------------------
  // Boolean
  // -------------------------------------------------------------------------

  it("infers boolean type", () => {
    const { schema, fields } = generateSchemaFromFields({ active: true });
    expect((schema.properties as Record<string, unknown>).active).toEqual({ type: "boolean" });
    expect(fields[0]).toMatchObject({ name: "active", type: "boolean" });
  });

  // -------------------------------------------------------------------------
  // Null
  // -------------------------------------------------------------------------

  it("defaults null to string", () => {
    const { schema, fields } = generateSchemaFromFields({ unknown: null });
    expect((schema.properties as Record<string, unknown>).unknown).toEqual({ type: "string" });
    expect(fields[0]).toMatchObject({ name: "unknown", type: "string" });
  });

  // -------------------------------------------------------------------------
  // Array
  // -------------------------------------------------------------------------

  it("infers array from first element", () => {
    const { schema, fields } = generateSchemaFromFields({ tags: ["alpha", "beta"] });
    expect((schema.properties as Record<string, unknown>).tags).toEqual({
      type: "array",
      items: { type: "string" },
    });
    expect(fields[0]).toMatchObject({ name: "tags", type: "array" });
  });

  it("handles empty array", () => {
    const { schema } = generateSchemaFromFields({ items: [] });
    expect((schema.properties as Record<string, unknown>).items).toEqual({
      type: "array",
      items: {},
    });
  });

  // -------------------------------------------------------------------------
  // Nested object
  // -------------------------------------------------------------------------

  it("recurses for nested objects", () => {
    const { schema, fields } = generateSchemaFromFields({
      address: { street: "123 Main St", zip: 12345 },
    });
    const addressProp = (schema.properties as Record<string, Record<string, unknown>>).address;
    expect(addressProp.type).toBe("object");
    expect(addressProp.properties).toEqual({
      street: { type: "string" },
      zip: { type: "integer" },
    });
    expect(addressProp.required).toEqual(["street", "zip"]);
    expect(fields[0]).toMatchObject({ name: "address", type: "object" });
  });

  // -------------------------------------------------------------------------
  // Empty input
  // -------------------------------------------------------------------------

  it("handles empty input", () => {
    const { schema, fields } = generateSchemaFromFields({});
    expect(schema.type).toBe("object");
    expect(schema.properties).toEqual({});
    expect(schema.required).toEqual([]);
    expect(fields).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // $schema declaration
  // -------------------------------------------------------------------------

  it("includes correct $schema declaration", () => {
    const { schema } = generateSchemaFromFields({ x: 1 });
    expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
  });

  // -------------------------------------------------------------------------
  // All fields in required
  // -------------------------------------------------------------------------

  it("puts all field names in required", () => {
    const { schema } = generateSchemaFromFields({ a: "x", b: 1, c: true });
    expect(schema.required).toEqual(["a", "b", "c"]);
  });

  // -------------------------------------------------------------------------
  // Round-trip: generate -> register -> validate
  // -------------------------------------------------------------------------

  it("round-trips through SchemaRegistry and Validator", () => {
    const { schema } = generateSchemaFromFields({
      name: "Alice",
      age: 30,
      email: "alice@example.com",
    });

    // AJV does not accept the $schema meta-schema URI in registered schemas
    const { $schema: _meta, ...schemaForValidation } = schema;

    const registry = new SchemaRegistry();
    registry.register({
      id: "test/dynamic/v1",
      schema: schemaForValidation,
      version: "1.0.0",
      lastUpdated: new Date().toISOString(),
      checksum: "0000000000000000000000000000000000000000000000000000000000000000",
      source: {
        kind: "defined",
        upstreamUrl: "https://example.com",
        upstreamOwner: "Test",
        upstreamLicense: "MIT",
      },
    });

    const validator = new Validator(registry);

    // Valid data should pass
    const validResult = validator.validateCredentialSubject("test/dynamic/v1", {
      name: "Bob",
      age: 25,
      email: "bob@example.com",
    });
    expect(validResult.valid).toBe(true);
    expect(validResult.errors).toHaveLength(0);

    // Invalid data should fail (age is string instead of integer)
    const invalidResult = validator.validateCredentialSubject("test/dynamic/v1", {
      name: "Bob",
      age: "not-a-number",
      email: "bob@example.com",
    });
    expect(invalidResult.valid).toBe(false);
    expect(invalidResult.errors.length).toBeGreaterThan(0);
  });
});
