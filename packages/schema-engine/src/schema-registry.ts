import { createHash } from "node:crypto";
import { NotFoundError } from "@opencred/shared";
import type { SchemaCategory, SchemaDefinition, SchemaManifest } from "./types.js";

export class SchemaRegistry {
  private readonly schemas = new Map<string, SchemaDefinition>();
  private readonly typeToContext = new Map<string, string>();
  private cachedManifest: SchemaManifest | null = null;

  /**
   * Register a fully-formed schema definition. Used by the build-time
   * generated registry to load every credential from manifest.json with
   * its hash and source provenance already populated.
   */
  register(def: SchemaDefinition): void {
    this.schemas.set(def.id, def);
    if (def.contextUrl) {
      this.typeToContext.set(def.id, def.contextUrl);
    }
    this.cachedManifest = null;
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

  /**
   * Return schemas grouped by category.
   * Schemas without a category are placed under "other".
   */
  listSchemasByCategory(): Record<SchemaCategory, string[]> {
    const grouped: Record<SchemaCategory, string[]> = {
      education: [],
      employment: [],
      identity: [],
      health: [],
      business: [],
      utility: [],
      "supply-chain": [],
      other: [],
    };
    for (const [id, def] of this.schemas) {
      const cat = def.category ?? "other";
      grouped[cat].push(id);
    }
    return grouped;
  }

  getContextForType(type: string): string | undefined {
    return this.typeToContext.get(type);
  }

  /**
   * Compute a SHA-256 checksum for a schema's JSON representation.
   * Kept for backward compatibility with downstream callers
   * (apps/desktop/src/main/ipc-handlers.ts) that hash user-supplied
   * schema bodies. New code should prefer canonicalJsonSha256 from
   * @opencred/shared.
   */
  static computeChecksum(schema: Record<string, unknown>): string {
    const canonical = JSON.stringify(schema);
    return createHash("sha256").update(canonical).digest("hex");
  }

  /**
   * Generate a manifest describing all registered schemas, their versions,
   * and pinned checksums.
   */
  getManifest(): SchemaManifest {
    if (this.cachedManifest) return this.cachedManifest;
    const schemas = [...this.schemas.values()].map((def) => ({
      id: def.id,
      version: def.version,
      checksum: def.checksum,
    }));
    this.cachedManifest = { schemas };
    return this.cachedManifest;
  }
}
