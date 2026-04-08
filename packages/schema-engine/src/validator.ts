import ajvModule, { type ErrorObject } from "ajv";
import ajvFormatsModule from "ajv-formats";
import { SchemaValidationError } from "@opencred/shared";
import type { SchemaRegistry } from "./schema-registry.js";
import type { ValidationResult, ValidationFieldError } from "./types.js";

// Handle CJS default export interop with Node16 module resolution
const Ajv = ajvModule.default ?? ajvModule;
const addFormats = ajvFormatsModule.default ?? ajvFormatsModule;

/**
 * Extract the JSON Schema that describes the `credentialSubject` shape.
 *
 * Supports two schema styles:
 *   - **Envelope schema (W3C VC 2.0 full envelope)** — the schema describes
 *     the entire VC including `@context`, `id`, `type`, `issuer`, `validFrom`,
 *     `credentialSubject`, etc. The subject sub-schema lives at
 *     `schema.properties.credentialSubject`. v1 library schemas authored by
 *     Stream A (electricity, immunization, prescription, etc.) use this
 *     style, modelled on the existing `electricity/v1` shape.
 *   - **Subject-only schema (legacy)** — the schema directly describes the
 *     subject fields. Pre-v1 generic schemas (education, employment, etc.)
 *     used this style.
 *
 * If the schema has `properties.credentialSubject` AND that sub-schema is a
 * non-empty object, return the sub-schema. Otherwise return the whole schema
 * as-is so legacy consumers keep working.
 *
 * The returned sub-schema is unlinked from the parent to avoid AJV resolving
 * `$ref` paths across schema boundaries for this ad-hoc compile — good enough
 * for the `credentialSubject` shape which doesn't cross-reference the envelope.
 */
function extractSubjectSchema(
  schema: Record<string, unknown>,
): Record<string, unknown> {
  const properties = schema["properties"];
  if (properties && typeof properties === "object") {
    const subject = (properties as Record<string, unknown>)["credentialSubject"];
    if (
      subject &&
      typeof subject === "object" &&
      !Array.isArray(subject) &&
      Object.keys(subject as Record<string, unknown>).length > 0
    ) {
      return subject as Record<string, unknown>;
    }
  }
  return schema;
}

export class Validator {
  private readonly ajv: InstanceType<typeof Ajv>;
  private readonly registry: SchemaRegistry;

  constructor(registry: SchemaRegistry) {
    this.registry = registry;
    this.ajv = new Ajv({ allErrors: true });
    addFormats(this.ajv);
  }

  validateCredentialSubject(schemaId: string, data: unknown): ValidationResult {
    const definition = this.registry.getSchema(schemaId);
    const subjectSchema = extractSubjectSchema(definition.schema);
    const validate = this.ajv.compile(subjectSchema);
    const valid = validate(data);

    if (valid) {
      return { valid: true, errors: [] };
    }

    const errors: ValidationFieldError[] = (validate.errors ?? []).map((err: ErrorObject) => ({
      field: err.instancePath
        ? err.instancePath.slice(1).replace(/\//g, ".")
        : ((err.params?.["missingProperty"] as string) ?? "(root)"),
      message: err.message ?? "Validation failed",
    }));

    return { valid: false, errors };
  }

  validateOrThrow(schemaId: string, data: unknown): void {
    const result = this.validateCredentialSubject(schemaId, data);
    if (!result.valid) {
      throw new SchemaValidationError(`Validation failed for schema "${schemaId}"`, result.errors);
    }
  }
}
