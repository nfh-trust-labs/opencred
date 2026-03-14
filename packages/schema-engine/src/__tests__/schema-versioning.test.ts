import { describe, it, expect, vi, afterEach } from "vitest";
import { createHash } from "node:crypto";
import { readFile, readdir, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { SchemaRegistry } from "../schema-registry.js";
import { createRegistry, getSchemaManifest } from "../index.js";
import {
  compareSemver,
  computeChecksum,
  checkForSchemaUpdates,
  downloadSchema,
  loadCachedSchemas,
  saveSchemasToCache,
  validateSchemaChecksum,
} from "../updater.js";
import type { SchemaDefinition, SchemaManifest } from "../types.js";

// ---------------------------------------------------------------------------
// Mock node:fs/promises
// ---------------------------------------------------------------------------
vi.mock("node:fs/promises", () => ({
  readFile: vi.fn(),
  readdir: vi.fn(),
  writeFile: vi.fn(),
  mkdir: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Mock global fetch
// ---------------------------------------------------------------------------
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

afterEach(() => {
  vi.restoreAllMocks();
  mockFetch.mockReset();
});

// ---------------------------------------------------------------------------
// Schema version metadata
// ---------------------------------------------------------------------------
describe("Schema version metadata", () => {
  it("SchemaDefinition includes version and lastUpdated", () => {
    const registry = new SchemaRegistry();
    registry.registerSchema(
      "test",
      { type: "object" },
      undefined,
      "2.0.0",
      "2025-06-01T00:00:00Z",
    );
    const def = registry.getSchema("test");
    expect(def.version).toBe("2.0.0");
    expect(def.lastUpdated).toBe("2025-06-01T00:00:00Z");
  });

  it("defaults version to 1.0.0 and lastUpdated when not provided", () => {
    const registry = new SchemaRegistry();
    registry.registerSchema("test", { type: "object" });
    const def = registry.getSchema("test");
    expect(def.version).toBe("1.0.0");
    expect(def.lastUpdated).toBe("2025-05-01T00:00:00Z");
  });

  it("createRegistry sets version on all bundled schemas", () => {
    const registry = createRegistry();
    for (const id of registry.listSchemas()) {
      const def = registry.getSchema(id);
      expect(def.version).toBe("1.0.0");
      expect(def.lastUpdated).toBe("2025-05-01T00:00:00Z");
    }
  });
});

// ---------------------------------------------------------------------------
// Schema manifest
// ---------------------------------------------------------------------------
describe("Schema manifest", () => {
  it("getManifest returns entries for all registered schemas", () => {
    const registry = new SchemaRegistry();
    registry.registerSchema("alpha", { type: "object", properties: {} }, undefined, "1.0.0");
    registry.registerSchema("beta", { type: "array", items: {} }, undefined, "2.0.0");

    const manifest = registry.getManifest();
    expect(manifest.schemas).toHaveLength(2);
    expect(manifest.schemas[0].id).toBe("alpha");
    expect(manifest.schemas[0].version).toBe("1.0.0");
    expect(manifest.schemas[1].id).toBe("beta");
    expect(manifest.schemas[1].version).toBe("2.0.0");
  });

  it("manifest checksums match computeChecksum", () => {
    const schema = { type: "object", required: ["name"], properties: { name: { type: "string" } } };
    const registry = new SchemaRegistry();
    registry.registerSchema("test", schema);

    const manifest = registry.getManifest();
    const expected = computeChecksum(schema);
    expect(manifest.schemas[0].checksum).toBe(expected);
  });

  it("getSchemaManifest returns manifest for all bundled schemas", () => {
    const manifest = getSchemaManifest();
    expect(manifest.schemas.length).toBe(5);
    const ids = manifest.schemas.map((s) => s.id);
    expect(ids).toContain("education");
    expect(ids).toContain("employment");
    expect(ids).toContain("identity");
    expect(ids).toContain("health");
    expect(ids).toContain("business");

    // All checksums should be non-empty hex strings
    for (const entry of manifest.schemas) {
      expect(entry.checksum).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.version).toBe("1.0.0");
    }
  });
});

// ---------------------------------------------------------------------------
// Checksum
// ---------------------------------------------------------------------------
describe("computeChecksum", () => {
  it("produces a SHA-256 hex digest", () => {
    const schema = { type: "object" };
    const checksum = computeChecksum(schema);
    expect(checksum).toMatch(/^[0-9a-f]{64}$/);
  });

  it("matches manual SHA-256 computation", () => {
    const schema = { type: "object", required: ["x"] };
    const expected = createHash("sha256").update(JSON.stringify(schema)).digest("hex");
    expect(computeChecksum(schema)).toBe(expected);
  });

  it("produces different checksums for different schemas", () => {
    const a = computeChecksum({ type: "object" });
    const b = computeChecksum({ type: "array" });
    expect(a).not.toBe(b);
  });

  it("is deterministic for identical schemas", () => {
    const schema = { a: 1, b: "two" };
    expect(computeChecksum(schema)).toBe(computeChecksum(schema));
  });
});

// ---------------------------------------------------------------------------
// Semver comparison
// ---------------------------------------------------------------------------
describe("compareSemver", () => {
  it("returns 0 for equal versions", () => {
    expect(compareSemver("1.0.0", "1.0.0")).toBe(0);
    expect(compareSemver("2.3.4", "2.3.4")).toBe(0);
  });

  it("returns positive when a > b (major)", () => {
    expect(compareSemver("2.0.0", "1.0.0")).toBeGreaterThan(0);
  });

  it("returns positive when a > b (minor)", () => {
    expect(compareSemver("1.2.0", "1.1.0")).toBeGreaterThan(0);
  });

  it("returns positive when a > b (patch)", () => {
    expect(compareSemver("1.0.2", "1.0.1")).toBeGreaterThan(0);
  });

  it("returns negative when a < b", () => {
    expect(compareSemver("1.0.0", "2.0.0")).toBeLessThan(0);
    expect(compareSemver("1.0.0", "1.1.0")).toBeLessThan(0);
    expect(compareSemver("1.0.0", "1.0.1")).toBeLessThan(0);
  });

  it("handles multi-digit version numbers", () => {
    expect(compareSemver("10.0.0", "9.0.0")).toBeGreaterThan(0);
    expect(compareSemver("1.20.0", "1.3.0")).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// checkForSchemaUpdates
// ---------------------------------------------------------------------------
describe("checkForSchemaUpdates", () => {
  const currentManifest: SchemaManifest = {
    schemas: [
      { id: "education", version: "1.0.0", checksum: "abc" },
      { id: "employment", version: "1.0.0", checksum: "def" },
    ],
  };

  it("detects newer versions in remote manifest", async () => {
    const remoteManifest: SchemaManifest = {
      schemas: [
        { id: "education", version: "1.1.0", checksum: "xyz" },
        { id: "employment", version: "1.0.0", checksum: "def" },
      ],
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(remoteManifest),
    });

    const result = await checkForSchemaUpdates(currentManifest, "https://example.com/schemas");
    expect(result.hasUpdates).toBe(true);
    expect(result.updatedIds).toEqual(["education"]);
    expect(result.remoteManifest).toEqual(remoteManifest);
  });

  it("detects new schemas not in current manifest", async () => {
    const remoteManifest: SchemaManifest = {
      schemas: [
        { id: "education", version: "1.0.0", checksum: "abc" },
        { id: "employment", version: "1.0.0", checksum: "def" },
        { id: "newschema", version: "1.0.0", checksum: "ghi" },
      ],
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(remoteManifest),
    });

    const result = await checkForSchemaUpdates(currentManifest, "https://example.com/schemas");
    expect(result.hasUpdates).toBe(true);
    expect(result.updatedIds).toEqual(["newschema"]);
  });

  it("returns hasUpdates=false when all versions match", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(currentManifest),
    });

    const result = await checkForSchemaUpdates(currentManifest, "https://example.com/schemas");
    expect(result.hasUpdates).toBe(false);
    expect(result.updatedIds).toEqual([]);
  });

  it("returns hasUpdates=false when remote has older versions", async () => {
    const olderManifest: SchemaManifest = {
      schemas: [
        { id: "education", version: "0.9.0", checksum: "old" },
        { id: "employment", version: "1.0.0", checksum: "def" },
      ],
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(olderManifest),
    });

    const result = await checkForSchemaUpdates(currentManifest, "https://example.com/schemas");
    expect(result.hasUpdates).toBe(false);
    expect(result.updatedIds).toEqual([]);
  });

  it("falls back gracefully on network error", async () => {
    mockFetch.mockRejectedValueOnce(new Error("Network error"));

    const result = await checkForSchemaUpdates(currentManifest, "https://example.com/schemas");
    expect(result.hasUpdates).toBe(false);
    expect(result.updatedIds).toEqual([]);
    expect(result.remoteManifest).toEqual(currentManifest);
  });

  it("falls back gracefully on non-OK response", async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });

    const result = await checkForSchemaUpdates(currentManifest, "https://example.com/schemas");
    expect(result.hasUpdates).toBe(false);
    expect(result.updatedIds).toEqual([]);
  });

  it("constructs correct manifest URL (without trailing slash)", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(currentManifest),
    });

    await checkForSchemaUpdates(currentManifest, "https://example.com/schemas");
    expect(mockFetch).toHaveBeenCalledWith("https://example.com/schemas/manifest.json");
  });

  it("constructs correct manifest URL (with trailing slash)", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(currentManifest),
    });

    await checkForSchemaUpdates(currentManifest, "https://example.com/schemas/");
    expect(mockFetch).toHaveBeenCalledWith("https://example.com/schemas/manifest.json");
  });
});

// ---------------------------------------------------------------------------
// downloadSchema
// ---------------------------------------------------------------------------
describe("downloadSchema", () => {
  it("downloads and returns a schema definition", async () => {
    const remoteDef: SchemaDefinition = {
      id: "education",
      schema: { type: "object" },
      version: "2.0.0",
      lastUpdated: "2025-06-01T00:00:00Z",
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(remoteDef),
    });

    const result = await downloadSchema("education", "https://example.com/schemas");
    expect(result).toEqual(remoteDef);
    expect(mockFetch).toHaveBeenCalledWith("https://example.com/schemas/schemas/education.json");
  });

  it("returns null on network error", async () => {
    mockFetch.mockRejectedValueOnce(new Error("Connection refused"));
    const result = await downloadSchema("education", "https://example.com/schemas");
    expect(result).toBeNull();
  });

  it("returns null on non-OK response", async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });
    const result = await downloadSchema("education", "https://example.com/schemas");
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Cache: loadCachedSchemas / saveSchemasToCache
// ---------------------------------------------------------------------------
describe("loadCachedSchemas", () => {
  it("loads valid schema files from cache directory", async () => {
    const schema1: SchemaDefinition = {
      id: "education",
      schema: { type: "object" },
      version: "1.0.0",
      lastUpdated: "2025-05-01T00:00:00Z",
    };

    vi.mocked(readdir).mockResolvedValueOnce(["education.json", "notes.txt"] as unknown as Awaited<
      ReturnType<typeof readdir>
    >);
    vi.mocked(readFile).mockResolvedValueOnce(JSON.stringify(schema1));

    const schemas = await loadCachedSchemas("/tmp/cache");
    expect(schemas).toHaveLength(1);
    expect(schemas[0].id).toBe("education");
    expect(schemas[0].version).toBe("1.0.0");
  });

  it("skips corrupt cache entries", async () => {
    vi.mocked(readdir).mockResolvedValueOnce(["bad.json", "good.json"] as unknown as Awaited<
      ReturnType<typeof readdir>
    >);
    vi.mocked(readFile)
      .mockResolvedValueOnce("not valid json{{{")
      .mockResolvedValueOnce(
        JSON.stringify({
          id: "good",
          schema: { type: "object" },
          version: "1.0.0",
          lastUpdated: "2025-05-01T00:00:00Z",
        }),
      );

    const schemas = await loadCachedSchemas("/tmp/cache");
    expect(schemas).toHaveLength(1);
    expect(schemas[0].id).toBe("good");
  });

  it("skips entries missing required fields", async () => {
    vi.mocked(readdir).mockResolvedValueOnce(["incomplete.json"] as unknown as Awaited<
      ReturnType<typeof readdir>
    >);
    vi.mocked(readFile).mockResolvedValueOnce(
      JSON.stringify({ id: "incomplete" }), // missing schema and version
    );

    const schemas = await loadCachedSchemas("/tmp/cache");
    expect(schemas).toHaveLength(0);
  });

  it("returns empty array when cache directory does not exist", async () => {
    vi.mocked(readdir).mockRejectedValueOnce(new Error("ENOENT"));
    const schemas = await loadCachedSchemas("/tmp/nonexistent");
    expect(schemas).toHaveLength(0);
  });
});

describe("saveSchemasToCache", () => {
  it("creates cache directory and writes schema files", async () => {
    vi.mocked(mkdir).mockResolvedValueOnce(undefined);
    vi.mocked(writeFile).mockResolvedValue(undefined);

    const schemas: SchemaDefinition[] = [
      {
        id: "education",
        schema: { type: "object" },
        version: "2.0.0",
        lastUpdated: "2025-06-01T00:00:00Z",
      },
    ];

    await saveSchemasToCache(schemas, "/tmp/cache");

    expect(mkdir).toHaveBeenCalledWith("/tmp/cache", { recursive: true });
    expect(writeFile).toHaveBeenCalledWith(
      join("/tmp/cache", "education.json"),
      JSON.stringify(schemas[0], null, 2),
      "utf-8",
    );
  });

  it("does not throw on write failure", async () => {
    vi.mocked(mkdir).mockRejectedValueOnce(new Error("EACCES"));

    const schemas: SchemaDefinition[] = [
      {
        id: "test",
        schema: { type: "object" },
        version: "1.0.0",
        lastUpdated: "2025-05-01T00:00:00Z",
      },
    ];

    // Should not throw
    await expect(saveSchemasToCache(schemas, "/tmp/readonly")).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// validateSchemaChecksum
// ---------------------------------------------------------------------------
describe("validateSchemaChecksum", () => {
  it("returns true when checksum matches", () => {
    const schema = { type: "object", required: ["name"] };
    const checksum = computeChecksum(schema);
    const def: SchemaDefinition = {
      id: "test",
      schema,
      version: "1.0.0",
      lastUpdated: "2025-05-01T00:00:00Z",
    };
    expect(validateSchemaChecksum(def, checksum)).toBe(true);
  });

  it("returns false when checksum does not match", () => {
    const def: SchemaDefinition = {
      id: "test",
      schema: { type: "object" },
      version: "1.0.0",
      lastUpdated: "2025-05-01T00:00:00Z",
    };
    expect(validateSchemaChecksum(def, "0000000000000000000000000000000000000000000000000000000000000000")).toBe(false);
  });
});
