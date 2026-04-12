import { describe, it, expect, vi, beforeEach } from "vitest";
import { createHash } from "node:crypto";
import { SchemaRegistry } from "../schema-registry.js";
import { checkForUpdates } from "../schema-updater.js";
import type { SchemaUpdateConfig, SchemaUpdateManifest } from "../schema-updater.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha256(json: string): string {
  return createHash("sha256").update(json).digest("hex");
}

function makeManifest(
  schemas: Array<{ id: string; version: string; schema: Record<string, unknown>; contextUrl?: string }>,
): SchemaUpdateManifest {
  return {
    version: 1,
    timestamp: "2026-04-12T00:00:00Z",
    schemas: schemas.map((s) => {
      const json = JSON.stringify(s.schema);
      return {
        id: s.id,
        version: s.version,
        checksum: sha256(json),
        downloadUrl: "https://schemas.example.com/" + s.id + ".json",
        contextUrl: s.contextUrl,
      };
    }),
  };
}

function seedRegistry(entries: Array<{ id: string; version: string; schema: Record<string, unknown> }>): SchemaRegistry {
  const registry = new SchemaRegistry();
  for (const e of entries) {
    registry.register({
      id: e.id,
      schema: e.schema,
      version: e.version,
      lastUpdated: "2026-01-01T00:00:00Z",
      checksum: sha256(JSON.stringify(e.schema)),
      source: {
        kind: "defined",
        upstreamUrl: "https://example.invalid/" + e.id,
        upstreamOwner: "OpenCred",
        upstreamLicense: "Apache-2.0",
      },
    });
  }
  return registry;
}

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockLookup = vi.fn();
vi.mock("node:dns/promises", () => ({
  default: { lookup: (...args: unknown[]) => mockLookup(...args) },
  lookup: (...args: unknown[]) => mockLookup(...args),
}));

vi.mock("node:fs/promises", () => ({
  mkdir: vi.fn().mockResolvedValue(undefined),
  readFile: vi.fn().mockRejectedValue(new Error("ENOENT")),
  writeFile: vi.fn().mockResolvedValue(undefined),
}));

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function makeConfig(overrides?: Partial<SchemaUpdateConfig>): SchemaUpdateConfig {
  return {
    manifestUrl: "https://schemas.example.com/manifest.json",
    cacheDir: "/tmp/test-schema-cache",
    timeoutMs: 5000,
    logger: { info: vi.fn(), warn: vi.fn() },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("checkForUpdates", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLookup.mockResolvedValue({ address: "93.184.216.34", family: 4 });
  });

  it("returns bundled registry unchanged when manifestUrl is not set", async () => {
    const registry = seedRegistry([
      { id: "alpha", version: "1.0.0", schema: { type: "object" } },
    ]);
    const config: SchemaUpdateConfig = { cacheDir: "/tmp/test" };

    const result = await checkForUpdates(config, registry);

    expect(result).toBe(registry);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("fetches, verifies checksum, and registers a new schema", async () => {
    const registry = seedRegistry([]);
    const newSchema = { type: "object", properties: { name: { type: "string" } } };
    const manifest = makeManifest([{ id: "beta", version: "1.0.0", schema: newSchema }]);
    const config = makeConfig();

    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(manifest),
      })
      .mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(JSON.stringify(newSchema)),
      });

    const result = await checkForUpdates(config, registry);

    expect(result.listSchemas()).toContain("beta");
    const def = result.getSchema("beta");
    expect(def.version).toBe("1.0.0");
    expect(def.checksum).toBe(sha256(JSON.stringify(newSchema)));
  });

  it("rejects schema with checksum mismatch", async () => {
    const registry = seedRegistry([]);
    const config = makeConfig();
    const manifest: SchemaUpdateManifest = {
      version: 1,
      timestamp: "2026-04-12T00:00:00Z",
      schemas: [
        {
          id: "bad",
          version: "1.0.0",
          checksum: "0".repeat(64),
          downloadUrl: "https://schemas.example.com/bad.json",
        },
      ],
    };

    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(manifest),
      })
      .mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(JSON.stringify({ type: "object" })),
      });

    const result = await checkForUpdates(config, registry);

    expect(result.listSchemas()).not.toContain("bad");
    expect(config.logger?.warn).toHaveBeenCalledWith(
      expect.stringContaining("Checksum mismatch"),
    );
  });

  it("falls back to bundled schemas on network failure", async () => {
    const registry = seedRegistry([
      { id: "alpha", version: "1.0.0", schema: { type: "object" } },
    ]);
    const config = makeConfig();

    mockFetch.mockRejectedValueOnce(new Error("Network error"));

    const result = await checkForUpdates(config, registry);

    expect(result).toBe(registry);
    expect(result.listSchemas()).toEqual(["alpha"]);
    expect(config.logger?.warn).toHaveBeenCalledWith(
      expect.stringContaining("Schema update check failed"),
    );
  });

  it("loads cached schema from disk when checksum matches", async () => {
    const { readFile } = await import("node:fs/promises");
    const cachedSchema = { type: "object", cached: true };
    const cachedJson = JSON.stringify(cachedSchema);
    vi.mocked(readFile).mockResolvedValueOnce(cachedJson);

    const registry = seedRegistry([]);
    const config = makeConfig();
    const manifest = makeManifest([{ id: "cached-one", version: "2.0.0", schema: cachedSchema }]);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(manifest),
    });

    const result = await checkForUpdates(config, registry);

    expect(result.listSchemas()).toContain("cached-one");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("rejects private IP in downloadUrl (SSRF protection)", async () => {
    const registry = seedRegistry([]);
    const config = makeConfig();
    const schema = { type: "object" };
    const manifest = makeManifest([{ id: "ssrf-test", version: "1.0.0", schema }]);

    mockLookup
      .mockResolvedValueOnce({ address: "93.184.216.34", family: 4 })
      .mockResolvedValueOnce({ address: "10.0.0.1", family: 4 });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(manifest),
    });

    const result = await checkForUpdates(config, registry);

    expect(result.listSchemas()).not.toContain("ssrf-test");
    expect(config.logger?.warn).toHaveBeenCalledWith(
      expect.stringContaining("Private IP rejected"),
    );
  });

  it("rejects non-HTTPS URL", async () => {
    const registry = seedRegistry([]);
    const config = makeConfig({
      manifestUrl: "http://schemas.example.com/manifest.json",
    });

    const result = await checkForUpdates(config, registry);

    expect(result).toBe(registry);
    expect(config.logger?.warn).toHaveBeenCalledWith(
      expect.stringContaining("Non-HTTPS URL rejected"),
    );
  });

  it("skips schema when bundled version is same or newer", async () => {
    const schema = { type: "object", properties: { x: { type: "number" } } };
    const registry = seedRegistry([
      { id: "stable", version: "2.0.0", schema },
    ]);
    const config = makeConfig();

    const manifest = makeManifest([
      { id: "stable", version: "1.5.0", schema },
    ]);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(manifest),
    });

    const result = await checkForUpdates(config, registry);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(result.getSchema("stable").version).toBe("2.0.0");
  });

  it("skips unsupported manifest version", async () => {
    const registry = seedRegistry([]);
    const config = makeConfig();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ version: 99, timestamp: "2026-04-12T00:00:00Z", schemas: [] }),
    });

    const result = await checkForUpdates(config, registry);

    expect(result).toBe(registry);
    expect(config.logger?.warn).toHaveBeenCalledWith(
      expect.stringContaining("Unsupported manifest version"),
    );
  });
});
