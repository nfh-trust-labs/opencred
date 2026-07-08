import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { canonicalJsonSha256 } from "@opencred/shared";

// The build script lives outside this package's tsc rootDir (src/), so we
// load it via a dynamic import URL constructed at runtime. tsc cannot follow
// the new URL() expression statically, which is exactly what we want.
type RunFn = (opts: {
  packageRoot: string;
  repoRoot: string;
  localTarballPath?: string;
  fetchImpl?: unknown;
  retryDelaysMs?: number[];
  allowStaleFallback?: boolean;
  logger?: { log?: (...a: unknown[]) => void; error?: (...a: unknown[]) => void };
}) => Promise<{
  records: Array<{ id: string }> | null;
  externalContexts: unknown[] | null;
  usedPriorEmbed: boolean;
}>;
let run: RunFn;
beforeAll(async () => {
  const url = new URL("../../scripts/fetch-and-embed-schemas.mjs", import.meta.url);
  const mod = (await import(url.href)) as { run: RunFn };
  run = mod.run;
});

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

const definedSchema = {
  $id: "https://example.invalid/test-schema-a/v1",
  type: "object",
  required: ["foo"],
  properties: { foo: { type: "string" } },
};

const referencedSchema = {
  $id: "https://w3id.org/test-fixture/schema",
  type: "object",
  required: ["bar"],
  properties: { bar: { type: "number" } },
};

const referencedUrl = "https://w3id.org/test-fixture/schema.json";

function buildManifest(extra: Record<string, unknown> = {}) {
  return {
    credentials: [
      {
        id: "test-schema-a/v1",
        source: "defined",
        owner: "OpenCred",
        license: "Apache-2.0",
        version: "1.0.0",
        lastUpdated: "2026-04-08T00:00:00Z",
        schema: {
          path: "schemas/test-schema-a/v1/schema.json",
          sha256: canonicalJsonSha256(definedSchema),
        },
      },
      {
        id: "test-referenced/v1",
        source: "referenced",
        owner: "W3C CCG",
        license: "W3C-20150513",
        version: "1.0.0",
        lastUpdated: "2026-04-08T00:00:00Z",
        schema: {
          url: referencedUrl,
          sha256: canonicalJsonSha256(referencedSchema),
        },
      },
    ],
    ...extra,
  };
}

/**
 * Build a fresh mock tarball at $TMPDIR/<unique>/source.tar.gz containing:
 *   opencred-vc-schemas-test/
 *     manifest.json
 *     schemas/test-schema-a/v1/schema.json
 *
 * Returns the absolute tarball path. Caller is responsible for rm()'ing the
 * surrounding tmpdir if needed (vitest cleans $TMPDIR on its own).
 */
async function buildMockTarball(opts: {
  manifest: unknown;
  definedSchemaContent?: unknown;
  omitDefinedFile?: boolean;
}): Promise<string> {
  const work = await mkdtemp(join(tmpdir(), "stream-b-mock-"));
  const root = join(work, "opencred-vc-schemas-test");
  await mkdir(join(root, "schemas", "test-schema-a", "v1"), { recursive: true });
  await writeFile(join(root, "manifest.json"), JSON.stringify(opts.manifest), "utf8");
  if (!opts.omitDefinedFile) {
    await writeFile(
      join(root, "schemas", "test-schema-a", "v1", "schema.json"),
      JSON.stringify(opts.definedSchemaContent ?? definedSchema),
      "utf8",
    );
  }
  const tarPath = join(work, "source.tar.gz");
  execFileSync("tar", ["-czf", tarPath, "-C", work, "opencred-vc-schemas-test"], {
    stdio: "ignore",
  });
  return tarPath;
}

/** Mock fetch that resolves the referenced URL to our fixture schema. */
function makeMockFetch(opts: { schema?: unknown; fail?: boolean } = {}) {
  return async (url: string | URL) => {
    const u = url.toString();
    if (u === referencedUrl) {
      if (opts.fail) {
        return {
          ok: false,
          status: 500,
          text: async () => "boom",
          arrayBuffer: async () => new ArrayBuffer(0),
        };
      }
      const body = JSON.stringify(opts.schema ?? referencedSchema);
      return {
        ok: true,
        status: 200,
        text: async () => body,
        arrayBuffer: async () => Buffer.from(body),
      };
    }
    throw new Error(`unexpected fetch: ${u}`);
  };
}

// Workspace where the script writes outputs. We sandbox the writes by
// pointing packageRoot at a fresh temp dir mirroring the package's
// `src/` and `scripts/` layout.
async function makeFakePackage(): Promise<{ pkgRoot: string; repoRoot: string }> {
  const root = await mkdtemp(join(tmpdir(), "stream-b-pkg-"));
  await mkdir(join(root, "src"), { recursive: true });
  await mkdir(join(root, "scripts"), { recursive: true });
  // schema-sources.json is required by run() — content is irrelevant
  // because we always pass localTarballPath.
  await writeFile(
    join(root, "scripts", "schema-sources.json"),
    JSON.stringify({ repo: "x/y", commit: "test", tarballSha256: null }),
  );
  const repoRoot = await mkdtemp(join(tmpdir(), "stream-b-repo-"));
  return { pkgRoot: root, repoRoot };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("fetch-and-embed-schemas (run)", () => {
  let pkgRoot: string;
  let repoRoot: string;
  const cleanups: string[] = [];

  beforeEach(async () => {
    const fp = await makeFakePackage();
    pkgRoot = fp.pkgRoot;
    repoRoot = fp.repoRoot;
    cleanups.push(pkgRoot, repoRoot);
  });

  afterEach(async () => {
    while (cleanups.length) {
      await rm(cleanups.pop()!, { recursive: true, force: true });
    }
  });

  it("happy path: generates schema-data.ts and generated-registry.ts and verifies hashes", async () => {
    const tarballPath = await buildMockTarball({ manifest: buildManifest() });
    const result = await run({
      packageRoot: pkgRoot,
      repoRoot,
      localTarballPath: tarballPath,
      fetchImpl: makeMockFetch(),
      logger: { log: () => {}, error: () => {} },
    });
    expect(result.records).toHaveLength(2);
    expect(result.records!.map((r: { id: string }) => r.id).sort()).toEqual([
      "test-referenced/v1",
      "test-schema-a/v1",
    ]);

    const schemaData = await readFile(join(pkgRoot, "src", "schema-data.ts"), "utf8");
    expect(schemaData).toContain("testSchemaAV1");
    expect(schemaData).toContain("testReferencedV1");

    const genReg = await readFile(join(pkgRoot, "src", "generated-registry.ts"), "utf8");
    expect(genReg).toContain("createBuiltInRegistry");
    expect(genReg).toContain('"test-schema-a/v1"');
    expect(genReg).toContain('"defined"');
    expect(genReg).toContain('"referenced"');
  });

  it("hard-fails on schema hash mismatch (defined)", async () => {
    // Build a tarball where the file content does NOT match the manifest hash.
    const manifest = buildManifest();
    const tarballPath = await buildMockTarball({
      manifest,
      definedSchemaContent: { ...definedSchema, mutated: true },
    });
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: makeMockFetch(),
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/hash mismatch.*test-schema-a/);
  });

  it("hard-fails when a defined schema file is missing from the tarball", async () => {
    const tarballPath = await buildMockTarball({
      manifest: buildManifest(),
      omitDefinedFile: true,
    });
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: makeMockFetch(),
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/schema file missing/);
  });

  it("hard-fails when a referenced URL host is not on the allowlist", async () => {
    const manifest = buildManifest();
    // Mutate the referenced URL to a non-allowlisted host.
    (manifest.credentials[1] as { schema: { url: string } }).schema.url =
      "https://evil.example.com/schema.json";
    const tarballPath = await buildMockTarball({ manifest });
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: makeMockFetch(),
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/not on allowlist/);
  });

  it("hard-fails on duplicate credential ids", async () => {
    const manifest = buildManifest();
    manifest.credentials.push({ ...manifest.credentials[0] });
    const tarballPath = await buildMockTarball({ manifest });
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: makeMockFetch(),
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/duplicate credential id/);
  });

  it("hard-fails when a referenced fetch returns non-200", async () => {
    const tarballPath = await buildMockTarball({ manifest: buildManifest() });
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: makeMockFetch({ fail: true }),
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/HTTP 500/);
  });
});

// ---------------------------------------------------------------------------
// Defined + YAML
// ---------------------------------------------------------------------------

const yamlSchemaText = `$id: https://example.invalid/test-yaml-defined/v1
type: object
required:
  - greeting
properties:
  greeting:
    type: string
`;

function sha256Hex(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

function buildYamlManifest(opts: { path: string; content: string; format?: "yaml" }) {
  const schema: Record<string, unknown> = {
    path: opts.path,
    sha256: sha256Hex(opts.content),
  };
  if (opts.format) schema.format = opts.format;
  return {
    credentials: [
      {
        id: "test-yaml-defined/v1",
        source: "defined",
        owner: "OpenCred",
        license: "Apache-2.0",
        version: "1.0.0",
        lastUpdated: "2026-04-08T00:00:00Z",
        schema,
      },
    ],
  };
}

async function buildYamlTarball(opts: {
  manifest: unknown;
  yamlContent: string;
  yamlRelPath: string;
}): Promise<string> {
  const work = await mkdtemp(join(tmpdir(), "stream-b-yaml-"));
  const root = join(work, "opencred-vc-schemas-test");
  const segments = opts.yamlRelPath.split("/");
  const fileName = segments.pop()!;
  await mkdir(join(root, ...segments), { recursive: true });
  await writeFile(join(root, "manifest.json"), JSON.stringify(opts.manifest), "utf8");
  await writeFile(join(root, ...segments, fileName), opts.yamlContent, "utf8");
  const tarPath = join(work, "source.tar.gz");
  execFileSync("tar", ["-czf", tarPath, "-C", work, "opencred-vc-schemas-test"], {
    stdio: "ignore",
  });
  return tarPath;
}

describe("fetch-and-embed-schemas (defined+YAML)", () => {
  let pkgRoot: string;
  let repoRoot: string;
  const cleanups: string[] = [];

  beforeEach(async () => {
    const fp = await makeFakePackage();
    pkgRoot = fp.pkgRoot;
    repoRoot = fp.repoRoot;
    cleanups.push(pkgRoot, repoRoot);
  });

  afterEach(async () => {
    while (cleanups.length) {
      await rm(cleanups.pop()!, { recursive: true, force: true });
    }
  });

  it("embeds a defined YAML schema detected by .yml suffix", async () => {
    const yamlRelPath = "schemas/test-yaml-defined/v1/schema.yml";
    const tarballPath = await buildYamlTarball({
      manifest: buildYamlManifest({ path: yamlRelPath, content: yamlSchemaText }),
      yamlContent: yamlSchemaText,
      yamlRelPath,
    });
    const result = await run({
      packageRoot: pkgRoot,
      repoRoot,
      localTarballPath: tarballPath,
      fetchImpl: makeMockFetch(),
      logger: { log: () => {}, error: () => {} },
    });
    expect(result.records).toHaveLength(1);
    expect(result.records![0].id).toBe("test-yaml-defined/v1");

    // YAML is parsed and re-emitted as JSON in schema-data.ts.
    const schemaData = await readFile(join(pkgRoot, "src", "schema-data.ts"), "utf8");
    expect(schemaData).toContain("testYamlDefinedV1");
    expect(schemaData).toContain('"greeting"');
    expect(schemaData).toContain('"type": "string"');

    // Checksum recorded in the registry is the raw-bytes hash of the YAML.
    const genReg = await readFile(join(pkgRoot, "src", "generated-registry.ts"), "utf8");
    expect(genReg).toContain(sha256Hex(yamlSchemaText));
  });

  it("detects YAML via explicit `format: yaml` even without a .yml suffix", async () => {
    const yamlRelPath = "schemas/test-yaml-defined/v1/schema";
    const tarballPath = await buildYamlTarball({
      manifest: buildYamlManifest({
        path: yamlRelPath,
        content: yamlSchemaText,
        format: "yaml",
      }),
      yamlContent: yamlSchemaText,
      yamlRelPath,
    });
    const result = await run({
      packageRoot: pkgRoot,
      repoRoot,
      localTarballPath: tarballPath,
      fetchImpl: makeMockFetch(),
      logger: { log: () => {}, error: () => {} },
    });
    expect(result.records).toHaveLength(1);
    expect(result.records![0].id).toBe("test-yaml-defined/v1");
  });

  it("hard-fails on raw-bytes hash mismatch", async () => {
    const yamlRelPath = "schemas/test-yaml-defined/v1/schema.yml";
    // Manifest hash is over `yamlSchemaText`, but the tarball ships a
    // whitespace-mutated version → byte hash diverges.
    const mutatedYaml = yamlSchemaText + "# tampered\n";
    const tarballPath = await buildYamlTarball({
      manifest: buildYamlManifest({ path: yamlRelPath, content: yamlSchemaText }),
      yamlContent: mutatedYaml,
      yamlRelPath,
    });
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: makeMockFetch(),
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/hash mismatch.*test-yaml-defined/);
  });

  it("hard-fails when defined YAML parses to a non-object", async () => {
    const yamlRelPath = "schemas/test-yaml-defined/v1/schema.yml";
    const scalarYaml = "42\n";
    const tarballPath = await buildYamlTarball({
      manifest: buildYamlManifest({ path: yamlRelPath, content: scalarYaml }),
      yamlContent: scalarYaml,
      yamlRelPath,
    });
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: makeMockFetch(),
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/parsed YAML is not an object/);
  });
});

// ---------------------------------------------------------------------------
// Network resilience: retry-with-backoff + stale-embed fallback
// ---------------------------------------------------------------------------

/** Mock fetch that fails the first `failures` referenced-URL calls, then succeeds. */
function makeFlakyFetch(opts: { failures: number; failWith?: "throw" | 429 }) {
  let calls = 0;
  const fetchImpl = async (url: string | URL) => {
    const u = url.toString();
    if (u !== referencedUrl) throw new Error(`unexpected fetch: ${u}`);
    calls++;
    if (calls <= opts.failures) {
      if (opts.failWith === 429) {
        return {
          ok: false,
          status: 429,
          text: async () => "rate limited",
          arrayBuffer: async () => new ArrayBuffer(0),
        };
      }
      throw new TypeError("fetch failed");
    }
    const body = JSON.stringify(referencedSchema);
    return {
      ok: true,
      status: 200,
      text: async () => body,
      arrayBuffer: async () => Buffer.from(body),
    };
  };
  return { fetchImpl, getCalls: () => calls };
}

const GENERATED_HEADER =
  "// AUTO-GENERATED by scripts/fetch-and-embed-schemas.mjs — do not edit by hand.\n";

/** Pre-populate the fake package with a prior generated embed. */
async function writePriorEmbed(pkgRoot: string): Promise<{ data: string; registry: string }> {
  const data = GENERATED_HEADER + "export const priorV1: Record<string, unknown> = {};\n";
  const registry = GENERATED_HEADER + "export function createBuiltInRegistry() {}\n";
  await writeFile(join(pkgRoot, "src", "schema-data.ts"), data, "utf8");
  await writeFile(join(pkgRoot, "src", "generated-registry.ts"), registry, "utf8");
  return { data, registry };
}

describe("fetch-and-embed-schemas (network resilience)", () => {
  let pkgRoot: string;
  let repoRoot: string;
  let tarballPath: string;
  const cleanups: string[] = [];

  beforeEach(async () => {
    const fp = await makeFakePackage();
    pkgRoot = fp.pkgRoot;
    repoRoot = fp.repoRoot;
    cleanups.push(pkgRoot, repoRoot);
    tarballPath = await buildMockTarball({ manifest: buildManifest() });
  });

  afterEach(async () => {
    vi.unstubAllEnvs();
    while (cleanups.length) {
      await rm(cleanups.pop()!, { recursive: true, force: true });
    }
  });

  it("retries network-level fetch failures and succeeds within 3 attempts", async () => {
    const flaky = makeFlakyFetch({ failures: 2 });
    const result = await run({
      packageRoot: pkgRoot,
      repoRoot,
      localTarballPath: tarballPath,
      fetchImpl: flaky.fetchImpl,
      retryDelaysMs: [1, 1],
      logger: { log: () => {}, error: () => {} },
    });
    expect(result.records).toHaveLength(2);
    expect(result.usedPriorEmbed).toBe(false);
    expect(flaky.getCalls()).toBe(3);
  });

  it("retries 429 responses with backoff", async () => {
    const flaky = makeFlakyFetch({ failures: 2, failWith: 429 });
    const result = await run({
      packageRoot: pkgRoot,
      repoRoot,
      localTarballPath: tarballPath,
      fetchImpl: flaky.fetchImpl,
      retryDelaysMs: [1, 1],
      logger: { log: () => {}, error: () => {} },
    });
    expect(result.records).toHaveLength(2);
    expect(flaky.getCalls()).toBe(3);
  });

  it("falls back to the prior embed on persistent network failure, loudly, without rewriting outputs", async () => {
    vi.stubEnv("CI", "");
    const prior = await writePriorEmbed(pkgRoot);
    const flaky = makeFlakyFetch({ failures: Infinity });
    const errors: string[] = [];
    const result = await run({
      packageRoot: pkgRoot,
      repoRoot,
      localTarballPath: tarballPath,
      fetchImpl: flaky.fetchImpl,
      retryDelaysMs: [1, 1],
      logger: { log: () => {}, error: (...a) => errors.push(a.join(" ")) },
    });
    expect(result.usedPriorEmbed).toBe(true);
    expect(result.records).toBeNull();
    // Warning is loud and names the staleness risk.
    expect(errors.join("\n")).toMatch(/WARNING/);
    expect(errors.join("\n")).toMatch(/STALE/);
    // Prior outputs are left exactly as they were.
    expect(await readFile(join(pkgRoot, "src", "schema-data.ts"), "utf8")).toBe(prior.data);
    expect(await readFile(join(pkgRoot, "src", "generated-registry.ts"), "utf8")).toBe(
      prior.registry,
    );
  });

  it("hard-fails on persistent network failure when no prior embed exists", async () => {
    vi.stubEnv("CI", "");
    const flaky = makeFlakyFetch({ failures: Infinity });
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: flaky.fetchImpl,
        retryDelaysMs: [1, 1],
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/network error fetching/);
  });

  it("hard-fails on persistent network failure in CI even when a prior embed exists", async () => {
    vi.stubEnv("CI", "true");
    await writePriorEmbed(pkgRoot);
    const flaky = makeFlakyFetch({ failures: Infinity });
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: flaky.fetchImpl,
        retryDelaysMs: [1, 1],
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/network error fetching/);
  });

  it("hard-fails when the fallback is explicitly disabled", async () => {
    vi.stubEnv("CI", "");
    await writePriorEmbed(pkgRoot);
    const flaky = makeFlakyFetch({ failures: Infinity });
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: flaky.fetchImpl,
        retryDelaysMs: [1, 1],
        allowStaleFallback: false,
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/network error fetching/);
  });

  it("does not fall back on non-network failures even with a prior embed", async () => {
    vi.stubEnv("CI", "");
    await writePriorEmbed(pkgRoot);
    await expect(
      run({
        packageRoot: pkgRoot,
        repoRoot,
        localTarballPath: tarballPath,
        fetchImpl: makeMockFetch({ fail: true }),
        retryDelaysMs: [1, 1],
        logger: { log: () => {}, error: () => {} },
      }),
    ).rejects.toThrow(/HTTP 500/);
  });
});
