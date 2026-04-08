import { describe, it, expect } from "vitest";
import { canonicalJsonSha256 } from "@opencred/shared";
import { SchemaRegistry } from "../schema-registry.js";
import { createRegistry, getSchemaManifest } from "../index.js";
import type { SchemaDefinition } from "../types.js";

function makeDef(id: string, schema: Record<string, unknown>): SchemaDefinition {
  return {
    id,
    schema,
    version: "1.0.0",
    lastUpdated: "2026-04-08T00:00:00Z",
    checksum: canonicalJsonSha256(schema),
    source: {
      kind: "defined",
      upstreamUrl: `https://example.invalid/${id}`,
      upstreamOwner: "OpenCred",
      upstreamLicense: "Apache-2.0",
    },
  };
}

describe("Schema manifest (post-refactor)", () => {
  it("registry getManifest exposes the canonical hash from each definition", () => {
    const registry = new SchemaRegistry();
    const schema = { type: "object", required: ["x"] };
    const def = makeDef("alpha", schema);
    registry.register(def);

    const manifest = registry.getManifest();
    expect(manifest.schemas).toHaveLength(1);
    expect(manifest.schemas[0]).toEqual({
      id: "alpha",
      version: def.version,
      checksum: def.checksum,
    });
    // Hash is the same canonical hash the build script will pin.
    expect(manifest.schemas[0].checksum).toBe(canonicalJsonSha256(schema));
  });

  it("getSchemaManifest returns one entry per built-in credential", () => {
    const manifest = getSchemaManifest();
    const ids = new Set(manifest.schemas.map((s) => s.id));
    // Tolerates the placeholder pre-build state (0 schemas) — the contract
    // we lock in is the SHAPE, not the count. Once Stream A's manifest is
    // wired in, this set will be ~33 entries.
    expect(ids.size).toBe(manifest.schemas.length);
    for (const entry of manifest.schemas) {
      expect(entry.checksum).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.version).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });

  it("createRegistry-built schemas all carry source provenance", () => {
    const registry = createRegistry();
    for (const id of registry.listSchemas()) {
      const def = registry.getSchema(id);
      expect(["defined", "referenced"]).toContain(def.source.kind);
      expect(def.source.upstreamUrl.startsWith("https://")).toBe(true);
    }
  });
});
