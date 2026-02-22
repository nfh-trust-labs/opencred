import ajvModule, { type ErrorObject } from "ajv";
import ajvFormatsModule from "ajv-formats";
import { SchemaValidationError } from "@opencred/shared";
import type { SchemaRegistry } from "./schema-registry.js";
import type { ValidationResult, ValidationFieldError } from "./types.js";

// Handle CJS default export interop with Node16 module resolution
const Ajv = ajvModule.default ?? ajvModule;
const addFormats = ajvFormatsModule.default ?? ajvFormatsModule;

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
    const validate = this.ajv.compile(definition.schema);
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
