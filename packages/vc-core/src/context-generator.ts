/**
 * Generates JSON-LD @context objects from JSON Schema definitions.
 *
 * Used for custom schemas: converts JSON Schema property types to JSON-LD
 * type annotations so that credential subjects are properly typed in JSON-LD.
 */

const XSD = "http://www.w3.org/2001/XMLSchema#";

interface JsonSchemaProperty {
  type?: string;
  format?: string;
  [key: string]: unknown;
}

interface JsonSchema {
  type: string;
  properties?: Record<string, JsonSchemaProperty>;
  [key: string]: unknown;
}

/**
 * Maps a JSON Schema property to a JSON-LD context entry.
 *
 * Returns a string (short form) for plain strings,
 * or an object with @id and @type (expanded form) for typed fields.
 */
function mapProperty(
  fieldName: string,
  prop: JsonSchemaProperty,
  namespaceUri: string,
): string | { "@id": string; "@type": string } {
  const id = `${namespaceUri}${fieldName}`;

  if (prop.type === "boolean") {
    return { "@id": id, "@type": `${XSD}boolean` };
  }
  if (prop.type === "integer") {
    return { "@id": id, "@type": `${XSD}integer` };
  }
  if (prop.type === "number") {
    return { "@id": id, "@type": `${XSD}double` };
  }

  // String with format
  if (prop.type === "string" && prop.format) {
    switch (prop.format) {
      case "date":
        return { "@id": id, "@type": `${XSD}date` };
      case "date-time":
        return { "@id": id, "@type": `${XSD}dateTime` };
      case "uri":
      case "url":
        return { "@id": id, "@type": "@id" };
      default:
        // email and other formats — just @id, no @type
        return id;
    }
  }

  // Plain string or unrecognized — short form
  return id;
}

/**
 * Converts a JSON Schema object to a JSON-LD `@context` object.
 *
 * @param schema - A JSON Schema with `type: "object"` and `properties`.
 * @param namespaceUri - The namespace URI prefix (e.g. "https://schema.nfh.global/vocab/education#").
 * @returns The inner context object (not wrapped in `{ "@context": ... }`).
 */
export function generateInlineContext(
  schema: JsonSchema,
  namespaceUri: string,
): Record<string, string | { "@id": string; "@type": string }> {
  const properties = schema.properties;
  if (!properties) {
    return {};
  }

  const context: Record<string, string | { "@id": string; "@type": string }> = {};

  for (const [fieldName, prop] of Object.entries(properties)) {
    context[fieldName] = mapProperty(fieldName, prop, namespaceUri);
  }

  return context;
}
