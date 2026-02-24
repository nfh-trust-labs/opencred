export type { SchemaDefinition, ValidationResult, ValidationFieldError } from "./types.js";
export { SchemaRegistry } from "./schema-registry.js";
export { Validator } from "./validator.js";
export {
  educationSchema,
  employmentSchema,
  identitySchema,
  healthSchema,
  businessSchema,
} from "./schemas/index.js";

import { SchemaRegistry } from "./schema-registry.js";
import {
  educationSchema,
  employmentSchema,
  identitySchema,
  healthSchema,
  businessSchema,
} from "./schemas/index.js";

export function createRegistry(): SchemaRegistry {
  const registry = new SchemaRegistry();

  registry.registerSchema(
    "education",
    educationSchema,
    "https://opencred.dev/contexts/education/v1",
  );
  registry.registerSchema(
    "employment",
    employmentSchema,
    "https://opencred.dev/contexts/employment/v1",
  );
  registry.registerSchema("identity", identitySchema, "https://opencred.dev/contexts/identity/v1");
  registry.registerSchema("health", healthSchema, "https://opencred.dev/contexts/health/v1");
  registry.registerSchema("business", businessSchema, "https://opencred.dev/contexts/business/v1");

  return registry;
}
