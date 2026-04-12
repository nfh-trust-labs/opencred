/**
 * Dynamic schema generation from sample data objects.
 *
 * Takes a record of field names to sample values and infers a JSON Schema
 * with appropriate types and formats. This allows issuers to define credential
 * schemas by providing example data rather than writing JSON Schema by hand.
 */

import type { InferredField, GeneratedSchemaResult } from "./types.js";

/** Email pattern for format detection. */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Infer a JSON Schema property definition from a sample value.
 *
 * Returns both the schema property object and the InferredField metadata.
 */
function inferProperty(value: unknown): {
  schemaProp: Record<string, unknown>;
  type: InferredField["type"];
  format?: InferredField["format"];
} {
  if (value === null) {
    return { schemaProp: { type: "string" }, type: "string" };
  }

  if (typeof value === "boolean") {
    return { schemaProp: { type: "boolean" }, type: "boolean" };
  }

  if (typeof value === "number") {
    if (Number.isInteger(value)) {
      return { schemaProp: { type: "integer" }, type: "integer" };
    }
    return { schemaProp: { type: "number" }, type: "number" };
  }

  if (typeof value === "string") {
    if (/^\d{4}-\d{2}-\d{2}T/.test(value)) {
      return {
        schemaProp: { type: "string", format: "date-time" },
        type: "string",
        format: "date-time",
      };
    }
    if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
      return {
        schemaProp: { type: "string", format: "date" },
        type: "string",
        format: "date",
      };
    }
    if (EMAIL_RE.test(value)) {
      return {
        schemaProp: { type: "string", format: "email" },
        type: "string",
        format: "email",
      };
    }
    if (/^https?:\/\//.test(value)) {
      return {
        schemaProp: { type: "string", format: "uri" },
        type: "string",
        format: "uri",
      };
    }
    return { schemaProp: { type: "string" }, type: "string" };
  }

  if (Array.isArray(value)) {
    if (value.length > 0) {
      const firstItem = inferProperty(value[0]);
      return {
        schemaProp: { type: "array", items: firstItem.schemaProp },
        type: "array",
      };
    }
    return { schemaProp: { type: "array", items: {} }, type: "array" };
  }

  if (typeof value === "object") {
    // Nested object — recurse
    const nested = generatePropertiesFromFields(value as Record<string, unknown>);
    return {
      schemaProp: {
        type: "object",
        properties: nested.properties,
        required: nested.required,
      },
      type: "object",
    };
  }

  return { schemaProp: { type: "string" }, type: "string" };
}

/**
 * Generate properties and required arrays from a fields object.
 */
function generatePropertiesFromFields(fields: Record<string, unknown>): {
  properties: Record<string, Record<string, unknown>>;
  required: string[];
  inferredFields: InferredField[];
} {
  const properties: Record<string, Record<string, unknown>> = {};
  const required: string[] = [];
  const inferredFields: InferredField[] = [];

  for (const [name, value] of Object.entries(fields)) {
    const inferred = inferProperty(value);
    properties[name] = inferred.schemaProp;
    required.push(name);
    inferredFields.push({
      name,
      type: inferred.type,
      ...(inferred.format ? { format: inferred.format } : {}),
      required: true,
    });
  }

  return { properties, required, inferredFields };
}

/**
 * Generate a JSON Schema from a sample data object.
 *
 * Takes a record of field names to sample values, infers types and formats,
 * and returns a complete JSON Schema along with field metadata.
 *
 * @param fields - A sample data object where keys are field names and values are sample data
 * @returns The generated JSON Schema and inferred field metadata
 */
export function generateSchemaFromFields(fields: Record<string, unknown>): GeneratedSchemaResult {
  const { properties, required, inferredFields } = generatePropertiesFromFields(fields);

  const schema: Record<string, unknown> = {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    properties,
    required,
  };

  return { schema, fields: inferredFields };
}
