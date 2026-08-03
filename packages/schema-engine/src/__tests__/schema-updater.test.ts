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
  schemas: Array<{
    id: string;
    version: string;
    schema: Record<string, unknown>;
    contextUrl?: string;
  }>,
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

function seedRegistry(
  entries: Array<{ id: string; version: string; schema: Record<string, unknown> }>,
): SchemaRegistry {
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

// `resolveDnsForSsrf` (the canonical SSRF helper) uses resolve4/resolve6
// from node:dns, so mock the underlying DNS promises API directly. Default
// each mock to a single public IP so tests that don't care about DNS
// resolution still pass.
const mockResolve4 = vi.fn();
const mockResolve6 = vi.fn();
vi.mock("node:dns", () => ({
  promises: {
    resolve4: (...args: unknown[]) => mockResolve4(...args),
    resolve6: (...args: unknown[]) => mockResolve6(...args),
  },
}));

vi.mock("node:fs/promises", () => ({
  mkdir: vi.fn().mockResolvedValue(undefined),
  readFile: vi.fn().mockRejectedValue(new Error("ENOENT")),
  writeFile: vi.fn().mockResolvedValue(undefined),
}));

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// `ssrfSafeFetch` pins the connection to the DNS-validated addresses via
// `fetchWithPinnedIp` (DNS-rebinding TOCTOU prevention). Delegate the pinned
// fetch to the global fetch stub so the existing tests keep a single mock
// surface; the SSRF/DNS validation logic itself stays real.
vi.mock("@opencred/shared", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    fetchWithPinnedIp: vi.fn((url: string | URL, _addresses: readonly string[], opts?: unknown) =>
      (globalThis.fetch as typeof fetch)(url, opts as RequestInit | undefined),
    ),
  };
});

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
    // Default: all DNS resolutions return a single public IP (A record only).
    // `resolveDnsForSsrf` tolerates ENODATA on AAAA when A succeeds.
    mockResolve4.mockResolvedValue(["93.184.216.34"]);
    const enodata = Object.assign(new Error("ENODATA"), { code: "ENODATA" });
    mockResolve6.mockRejectedValue(enodata);
  });

  it("returns bundled registry unchanged when manifestUrl is not set", async () => {
    const registry = seedRegistry([{ id: "alpha", version: "1.0.0", schema: { type: "object" } }]);
    const config: SchemaUpdateConfig = { cacheDir: "/tmp/test" };

    const result = await checkForUpdates(config, registry);

    expect(result).toBe(registry);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("pins the DNS-validated addresses for the manifest fetch (DNS rebinding)", async () => {
    const registry = seedRegistry([]);
    const manifest = makeManifest([]);
    mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(manifest) });

    await checkForUpdates(makeConfig(), registry);

    const { fetchWithPinnedIp } = await import("@opencred/shared");
    expect(vi.mocked(fetchWithPinnedIp)).toHaveBeenCalledWith(
      "https://schemas.example.com/manifest.json",
      ["93.184.216.34"],
      expect.anything(),
    );
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
    expect(config.logger?.warn).toHaveBeenCalledWith(expect.stringContaining("Checksum mismatch"));
  });

  it("falls back to bundled schemas on network failure", async () => {
    const registry = seedRegistry([{ id: "alpha", version: "1.0.0", schema: { type: "object" } }]);
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

    // Manifest hostname → public IP (first lookup). Download URL hostname →
    // private IP (second lookup), which `resolveDnsForSsrf` rejects with a
    // message containing "SSRF protection".
    mockResolve4.mockResolvedValueOnce(["93.184.216.34"]).mockResolvedValueOnce(["10.0.0.1"]);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(manifest),
    });

    const result = await checkForUpdates(config, registry);

    expect(result.listSchemas()).not.toContain("ssrf-test");
    expect(config.logger?.warn).toHaveBeenCalledWith(expect.stringContaining("SSRF protection"));
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
    const registry = seedRegistry([{ id: "stable", version: "2.0.0", schema }]);
    const config = makeConfig();

    const manifest = makeManifest([{ id: "stable", version: "1.5.0", schema }]);

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

  // ---------------------------------------------------------------------------
  // Origin-enforcement tests (downloadUrl must share manifest origin)
  // ---------------------------------------------------------------------------

  it("fetches when downloadUrl shares the manifest origin", async () => {
    const registry = seedRegistry([]);
    const schema = { type: "object", properties: { a: { type: "string" } } };
    const schemaJson = JSON.stringify(schema);
    const manifest: SchemaUpdateManifest = {
      version: 1,
      timestamp: "2026-04-12T00:00:00Z",
      schemas: [
        {
          id: "same-origin",
          version: "1.0.0",
          checksum: sha256(schemaJson),
          downloadUrl: "https://a.example.com/schemas/1.json",
        },
      ],
    };
    const config = makeConfig({
      manifestUrl: "https://a.example.com/manifest.json",
    });

    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(manifest),
      })
      .mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(schemaJson),
      });

    const result = await checkForUpdates(config, registry);

    expect(result.listSchemas()).toContain("same-origin");
    // Manifest fetch + download fetch = 2 calls
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("skips schema when downloadUrl origin differs from manifest origin", async () => {
    const registry = seedRegistry([]);
    const schema = { type: "object" };
    const schemaJson = JSON.stringify(schema);
    const manifest: SchemaUpdateManifest = {
      version: 1,
      timestamp: "2026-04-12T00:00:00Z",
      schemas: [
        {
          id: "cross-origin",
          version: "1.0.0",
          checksum: sha256(schemaJson),
          downloadUrl: "https://b.example.com/schemas/1.json",
        },
      ],
    };
    const config = makeConfig({
      manifestUrl: "https://a.example.com/manifest.json",
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(manifest),
    });

    const result = await checkForUpdates(config, registry);

    expect(result.listSchemas()).not.toContain("cross-origin");
    // Only the manifest was fetched — cross-origin download was rejected
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(config.logger?.warn).toHaveBeenCalledWith(
      expect.stringContaining("differs from manifest origin"),
    );
  });

  it("skips schema when downloadUrl is not a valid URL", async () => {
    const registry = seedRegistry([]);
    const manifest: SchemaUpdateManifest = {
      version: 1,
      timestamp: "2026-04-12T00:00:00Z",
      schemas: [
        {
          id: "bad-url",
          version: "1.0.0",
          checksum: sha256(JSON.stringify({ type: "object" })),
          downloadUrl: "not a url",
        },
      ],
    };
    const config = makeConfig();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(manifest),
    });

    const result = await checkForUpdates(config, registry);

    expect(result.listSchemas()).not.toContain("bad-url");
    // Only the manifest was fetched — invalid downloadUrl was rejected before fetch
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(config.logger?.warn).toHaveBeenCalledWith(
      expect.stringContaining("downloadUrl is not a valid URL"),
    );
  });

  it("rejects when scheme differs (http manifest vs https download)", async () => {
    // Note: an http:// manifestUrl is rejected by ssrfSafeFetch before we
    // reach the loop, so the origin check also needs to be demonstrated
    // with a matched-scheme-but-different-port variant. We model the
    // "scheme/port differ → different origin" invariant here.
    const registry = seedRegistry([]);
    const schema = { type: "object" };
    const schemaJson = JSON.stringify(schema);
    const manifest: SchemaUpdateManifest = {
      version: 1,
      timestamp: "2026-04-12T00:00:00Z",
      schemas: [
        {
          id: "different-port",
          version: "1.0.0",
          checksum: sha256(schemaJson),
          // Same host and scheme, different port → different origin.
          downloadUrl: "https://a.example.com:8443/schemas/1.json",
        },
      ],
    };
    const config = makeConfig({
      manifestUrl: "https://a.example.com/manifest.json",
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(manifest),
    });

    const result = await checkForUpdates(config, registry);

    expect(result.listSchemas()).not.toContain("different-port");
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(config.logger?.warn).toHaveBeenCalledWith(
      expect.stringContaining("differs from manifest origin"),
    );
  });

  it("rejects when scheme differs (https manifest vs http download)", async () => {
    const registry = seedRegistry([]);
    const schema = { type: "object" };
    const schemaJson = JSON.stringify(schema);
    const manifest: SchemaUpdateManifest = {
      version: 1,
      timestamp: "2026-04-12T00:00:00Z",
      schemas: [
        {
          id: "different-scheme",
          version: "1.0.0",
          checksum: sha256(schemaJson),
          // http scheme vs https manifest → different origin.
          downloadUrl: "http://a.example.com/schemas/1.json",
        },
      ],
    };
    const config = makeConfig({
      manifestUrl: "https://a.example.com/manifest.json",
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(manifest),
    });

    const result = await checkForUpdates(config, registry);

    expect(result.listSchemas()).not.toContain("different-scheme");
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(config.logger?.warn).toHaveBeenCalledWith(
      expect.stringContaining("differs from manifest origin"),
    );
  });
});
