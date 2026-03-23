/**
 * Schema inference utilities for the blank credential builder.
 *
 * Pure functions (renderer-safe, no IPC):
 *   - fieldsToJsonSchema: convert visual field builder output to JSON Schema
 *   - jsonToFields: infer field definitions from sample JSON
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FieldDefinition {
  name: string;
  type: "string" | "number" | "date" | "email" | "url";
  required: boolean;
}

// ---------------------------------------------------------------------------
// fieldsToJsonSchema
// ---------------------------------------------------------------------------

/** Convert visual field builder output to a JSON Schema. */
export function fieldsToJsonSchema(
  fields: FieldDefinition[],
): Record<string, unknown> {
  const properties: Record<string, Record<string, unknown>> = {};
  const required: string[] = [];

  for (const field of fields) {
    const prop: Record<string, unknown> = {};

    switch (field.type) {
      case "number":
        prop.type = "number";
        break;
      case "date":
        prop.type = "string";
        prop.format = "date";
        break;
      case "email":
        prop.type = "string";
        prop.format = "email";
        break;
      case "url":
        prop.type = "string";
        prop.format = "uri";
        break;
      default:
        prop.type = "string";
    }

    properties[field.name] = prop;
    if (field.required) {
      required.push(field.name);
    }
  }

  return {
    type: "object",
    properties,
    ...(required.length > 0 ? { required } : {}),
  };
}

// ---------------------------------------------------------------------------
// jsonToFields
// ---------------------------------------------------------------------------

/** ISO 8601 date pattern (YYYY-MM-DD). */
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?/;

/** Simple email pattern. */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** URL pattern. */
const URL_RE = /^https?:\/\//;

/** Infer the field type from a sample value. */
function inferType(value: unknown): FieldDefinition["type"] {
  if (typeof value === "number") return "number";
  if (typeof value !== "string") return "string";

  if (ISO_DATE_RE.test(value)) return "date";
  if (EMAIL_RE.test(value)) return "email";
  if (URL_RE.test(value)) return "url";

  // Check if it's a parseable number
  if (value.length > 0 && !isNaN(Number(value))) return "number";

  return "string";
}

/**
 * Infer field definitions from a sample JSON object.
 *
 * Top-level keys become field names. Nested objects are skipped.
 * Type is inferred from the sample value.
 */
export function jsonToFields(json: Record<string, unknown>): FieldDefinition[] {
  return Object.entries(json)
    .filter(([, value]) => typeof value !== "object" || value === null)
    .map(([name, value]) => ({
      name,
      type: inferType(value),
      required: true,
    }));
}
