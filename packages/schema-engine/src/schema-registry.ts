import { createHash } from "node:crypto";
import { NotFoundError } from "@opencred/shared";
import type { SchemaDefinition, SchemaManifest } from "./types.js";

export class SchemaRegistry {
  private readonly schemas = new Map<string, SchemaDefinition>();
  private readonly typeToContext = new Map<string, string>();
  private cachedManifest: SchemaManifest | null = null;

  registerSchema(
    id: string,
    schema: Record<string, unknown>,
    contextUrl?: string,
    version = "1.0.0",
    lastUpdated = "2025-05-01T00:00:00Z",
  ): void {
    const definition: SchemaDefinition = { id, schema, contextUrl, version, lastUpdated };
    this.schemas.set(id, definition);
    if (contextUrl) {
      this.typeToContext.set(id, contextUrl);
    }
    this.cachedManifest = null; // invalidate on registration
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

  /**
   * Compute a SHA-256 checksum for a schema's JSON representation.
   * This is used for integrity verification when caching/updating schemas.
   */
  static computeChecksum(schema: Record<string, unknown>): string {
    const canonical = JSON.stringify(schema);
    return createHash("sha256").update(canonical).digest("hex");
  }

  /**
   * Generate a manifest describing all registered schemas, their versions,
   * and checksums. Used for update-checking against a remote manifest.
   */
  getManifest(): SchemaManifest {
    if (this.cachedManifest) return this.cachedManifest;
    const schemas = [...this.schemas.values()].map((def) => ({
      id: def.id,
      version: def.version,
      checksum: SchemaRegistry.computeChecksum(def.schema),
    }));
    this.cachedManifest = { schemas };
    return this.cachedManifest;
  }
}
