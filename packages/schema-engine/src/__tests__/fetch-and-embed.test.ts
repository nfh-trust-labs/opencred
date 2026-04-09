import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  logger?: { log?: (...a: unknown[]) => void; error?: (...a: unknown[]) => void };
}) => Promise<{ records: Array<{ id: string }>; externalContexts: unknown[] }>;
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
    expect(result.records.map((r: { id: string }) => r.id).sort()).toEqual([
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
