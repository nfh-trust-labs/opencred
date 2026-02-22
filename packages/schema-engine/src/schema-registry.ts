import { NotFoundError } from "@opencred/shared";
import type { SchemaDefinition } from "./types.js";

export class SchemaRegistry {
  private readonly schemas = new Map<string, SchemaDefinition>();
  private readonly typeToContext = new Map<string, string>();

  registerSchema(id: string, schema: Record<string, unknown>, contextUrl?: string): void {
    const definition: SchemaDefinition = { id, schema, contextUrl };
    this.schemas.set(id, definition);
    if (contextUrl) {
      this.typeToContext.set(id, contextUrl);
    }
  }

  getSchema(id: string): SchemaDefinition {
    const schema = this.schemas.get(id);
    if (!schema) {
      throw new NotFoundError(`Schema not found: ${id}`);
    }
    return schema;
  }

  listSchemas(): string[] {
    return [...this.schemas.keys()];
  }

  getContextForType(type: string): string | undefined {
    return this.typeToContext.get(type);
  }
}
