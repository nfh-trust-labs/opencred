#!/usr/bin/env node
/**
 * Build-time script: fetch opencred-vc-schemas at a pinned commit, verify
 * SHA-256 hashes against the manifest, and generate bundled schema modules.
 *
 * Security invariants:
 *  - All runtime schema loading is from these bundled outputs. The runtime
 *    NEVER fetches remote schemas — only this build script touches the network,
 *    and it does so against a pinned commit + hash-verified content.
 *  - HTTPS only, no redirects, 30s timeout on every network call.
 *  - Referenced schema URLs must be on the host allowlist below.
 *  - Any failure (hash mismatch, missing file, network error, schema not on
 *    allowlist, duplicate id) hard-fails the build with a clear error.
 *  - One retry on 429/503 with a 1s delay; otherwise no retries.
 */

import { readFile, writeFile, mkdir, rm, mkdtemp } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { canonicalJsonSha256 } from "@opencred/shared";
import YAML from "yaml";

const HOST_ALLOWLIST = [
  { host: "w3id.org", pathPrefix: "/" },
  { host: "purl.imsglobal.org", pathPrefix: "/" },
  { host: "raw.githubusercontent.com", pathPrefix: "/nfh-trust-labs/" },
  { host: "raw.githubusercontent.com", pathPrefix: "/decentralized-identity/" },
  { host: "raw.githubusercontent.com", pathPrefix: "/w3c-ccg/traceability-vocab/" },
];

const NETWORK_TIMEOUT_MS = 30_000;

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

function sha256Bytes(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function isHostAllowed(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  return HOST_ALLOWLIST.some(
    (entry) => u.hostname === entry.host && u.pathname.startsWith(entry.pathPrefix),
  );
}

/** camelCase id → identifier. e.g. "traceability/commercial-invoice/v1" → "traceabilityCommercialInvoiceV1". */
export function idToConst(id) {
  const parts = id.split(/[/\-_]+/).filter(Boolean);
  return parts
    .map((p, i) => (i === 0 ? p.toLowerCase() : p[0].toUpperCase() + p.slice(1).toLowerCase()))
    .join("");
}

/** id → filename-safe slug. e.g. "traceability/commercial-invoice/v1" → "traceability-commercial-invoice-v1". */
export function idToFilename(id) {
  return id.replace(/\//g, "-");
}

async function fetchWithTimeoutAndRetry(url, fetchImpl) {
  const attempt = async () => {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), NETWORK_TIMEOUT_MS);
    try {
      const res = await fetchImpl(url, {
        redirect: "error",
        signal: controller.signal,
      });
      return res;
    } finally {
      clearTimeout(t);
    }
  };
  let res;
  try {
    res = await attempt();
  } catch (err) {
    throw new Error(`network error fetching ${url}: ${err.message ?? err}`);
  }
  if (res.status === 429 || res.status === 503) {
    await new Promise((r) => setTimeout(r, 1000));
    res = await attempt();
  }
  if (!res.ok) {
    throw new Error(`fetch ${url} failed: HTTP ${res.status}`);
  }
  return res;
}

/* ------------------------------------------------------------------ */
/* Tarball                                                            */
/* ------------------------------------------------------------------ */

async function obtainTarball({ sources, fetchImpl, localTarballPath }) {
  if (localTarballPath) {
    return await readFile(localTarballPath);
  }
  const url = `https://codeload.github.com/${sources.repo}/tar.gz/${sources.commit}`;
  const res = await fetchWithTimeoutAndRetry(url, fetchImpl);
  return Buffer.from(await res.arrayBuffer());
}

async function extractTarball(buf, destDir) {
  await mkdir(destDir, { recursive: true });
  const tarPath = join(destDir, "source.tar.gz");
  await writeFile(tarPath, buf);
  // Use system tar — present on macOS/Linux build hosts and CI.
  execFileSync("tar", ["-xzf", tarPath, "-C", destDir], { stdio: "ignore" });
}

/** Find the single top-level directory inside the extracted tarball. */
async function findExtractedRoot(extractDir) {
  const { readdir } = await import("node:fs/promises");
  const entries = await readdir(extractDir, { withFileTypes: true });
  const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name);
  if (dirs.length !== 1) {
    throw new Error(
      `expected exactly one top-level directory in extracted tarball, got: ${dirs.join(", ") || "(none)"}`,
    );
  }
  return join(extractDir, dirs[0]);
}

/* ------------------------------------------------------------------ */
/* Output generation                                                  */
/* ------------------------------------------------------------------ */

function renderSchemaDataModule(records) {
  const lines = [
    "// AUTO-GENERATED by scripts/fetch-and-embed-schemas.mjs — do not edit by hand.",
    "// Regenerate via `pnpm --filter @opencred/schema-engine build`.",
    "",
  ];
  for (const r of records) {
    lines.push(
      `export const ${r.constName}: Record<string, unknown> = ${JSON.stringify(r.schema, null, 2)};`,
    );
    lines.push("");
  }
  return lines.join("\n");
}

function renderGeneratedRegistryModule(records) {
  const lines = [
    "// AUTO-GENERATED by scripts/fetch-and-embed-schemas.mjs — do not edit by hand.",
    "// Regenerate via `pnpm --filter @opencred/schema-engine build`.",
    "",
    'import { SchemaRegistry } from "./schema-registry.js";',
    'import type { SchemaDefinition } from "./types.js";',
    "import {",
  ];
  for (const r of records) lines.push(`  ${r.constName},`);
  lines.push('} from "./schema-data.js";', "");
  lines.push("export function createBuiltInRegistry(): SchemaRegistry {");
  lines.push("  const registry = new SchemaRegistry();");
  for (const r of records) {
    const def = {
      id: r.id,
      version: r.version,
      lastUpdated: r.lastUpdated,
      checksum: r.checksum,
      contextUrl: r.contextUrl,
      source: r.source,
    };
    lines.push("  registry.register({");
    lines.push(`    id: ${JSON.stringify(def.id)},`);
    lines.push(`    schema: ${r.constName},`);
    if (def.contextUrl) lines.push(`    contextUrl: ${JSON.stringify(def.contextUrl)},`);
    lines.push(`    version: ${JSON.stringify(def.version)},`);
    lines.push(`    lastUpdated: ${JSON.stringify(def.lastUpdated)},`);
    lines.push(`    checksum: ${JSON.stringify(def.checksum)},`);
    lines.push(`    source: ${JSON.stringify(def.source)},`);
    lines.push("  } satisfies SchemaDefinition);");
  }
  lines.push("  return registry;");
  lines.push("}");
  lines.push("");
  return lines.join("\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

/**
 * Run the fetch-and-embed pipeline. Exposed as a function so tests can drive
 * it without forking a subprocess.
 *
 * @param {object} opts
 * @param {string} opts.packageRoot     — absolute path to packages/schema-engine
 * @param {string} opts.repoRoot        — absolute path to monorepo root
 * @param {string} [opts.sourcesPath]   — override path to schema-sources.json
 * @param {string} [opts.localTarballPath] — use a local tarball instead of fetching
 * @param {Function} [opts.fetchImpl]   — fetch implementation (for tests)
 * @param {object} [opts.logger]        — { log, error }
 */
export async function run(opts) {
  const log = opts.logger?.log ?? ((...a) => console.log(...a));
  const err = opts.logger?.error ?? ((...a) => console.error(...a));
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;

  const sourcesPath = opts.sourcesPath ?? join(opts.packageRoot, "scripts", "schema-sources.json");
  const sourcesRaw = await readFile(sourcesPath, "utf8");
  const sources = JSON.parse(sourcesRaw);
  if (!sources.repo || !sources.commit) {
    throw new Error(`schema-sources.json missing required fields: ${sourcesPath}`);
  }

  const tarballBuf = await obtainTarball({ sources, fetchImpl, localTarballPath: opts.localTarballPath });

  if (sources.tarballSha256) {
    const actual = sha256Bytes(tarballBuf);
    if (actual !== sources.tarballSha256) {
      throw new Error(
        `tarball SHA-256 mismatch: expected ${sources.tarballSha256}, got ${actual}`,
      );
    }
  }

  const extractDir = await mkdtemp(join(tmpdir(), `opencred-vc-schemas-${sources.commit}-`));
  try {
    await extractTarball(tarballBuf, extractDir);
    const extractedRoot = await findExtractedRoot(extractDir);

    const manifestPath = join(extractedRoot, "manifest.json");
    if (!existsSync(manifestPath)) {
      throw new Error(`manifest.json not found at ${manifestPath}`);
    }
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    if (!Array.isArray(manifest.credentials)) {
      throw new Error("manifest.json: missing or malformed `credentials` array");
    }

    // Detect duplicate ids
    const seen = new Set();
    for (const c of manifest.credentials) {
      if (!c.id) throw new Error("manifest credential missing `id`");
      if (seen.has(c.id)) throw new Error(`duplicate credential id in manifest: ${c.id}`);
      seen.add(c.id);
    }

    const records = [];
    const externalContexts = []; // { filename, bytes }

    for (const cred of manifest.credentials) {
      const sourceKind = cred.source;
      if (sourceKind !== "defined" && sourceKind !== "referenced") {
        throw new Error(`credential ${cred.id}: invalid source ${sourceKind}`);
      }
      if (!cred.schema || typeof cred.schema.sha256 !== "string") {
        throw new Error(`credential ${cred.id}: missing schema.sha256`);
      }

      let schemaObj;
      let schemaUpstreamUrl;
      let actualHash;

      // Format detection: `format: "yaml"` in the manifest, or a .yml/.yaml
      // URL or path, means the authoritative bytes are YAML and the manifest
      // hash is over the raw UTF-8 bytes (not canonicalized JSON). Otherwise
      // JSON.
      const urlLower = (cred.schema.url ?? "").toLowerCase();
      const pathLower = (cred.schema.path ?? "").toLowerCase();
      const isYaml =
        cred.schema.format === "yaml" ||
        urlLower.endsWith(".yml") ||
        urlLower.endsWith(".yaml") ||
        pathLower.endsWith(".yml") ||
        pathLower.endsWith(".yaml");

      if (sourceKind === "defined") {
        if (!cred.schema.path) {
          throw new Error(`credential ${cred.id}: defined schema missing schema.path`);
        }
        const localPath = join(extractedRoot, cred.schema.path);
        if (!existsSync(localPath)) {
          throw new Error(`credential ${cred.id}: schema file missing in tarball: ${cred.schema.path}`);
        }
        schemaUpstreamUrl =
          cred.schema.upstreamUrl ??
          `https://raw.githubusercontent.com/${sources.repo}/${sources.commit}/${cred.schema.path}`;
        if (isYaml) {
          // YAML path: hash the raw bytes, then parse to JS for bundling.
          // Raw-bytes hashing (rather than canonicalJsonSha256 of the parsed
          // result) matches the referenced-YAML convention and preserves
          // fidelity — YAML features like comments and anchors do not survive
          // a parse→canonical-JSON round trip, so the bytes are the
          // authoritative artifact.
          const buf = await readFile(localPath);
          actualHash = sha256Bytes(buf);
          if (actualHash !== cred.schema.sha256) {
            err(
              `\nHASH MISMATCH for credential "${cred.id}":\n  expected: ${cred.schema.sha256}\n  actual:   ${actualHash}\n`,
            );
            throw new Error(`schema hash mismatch for ${cred.id}`);
          }
          try {
            schemaObj = YAML.parse(buf.toString("utf8"));
          } catch (e) {
            throw new Error(`credential ${cred.id}: schema YAML is not parseable: ${e.message}`);
          }
          if (!schemaObj || typeof schemaObj !== "object") {
            throw new Error(`credential ${cred.id}: parsed YAML is not an object`);
          }
        } else {
          const text = await readFile(localPath, "utf8");
          schemaObj = JSON.parse(text);
          actualHash = canonicalJsonSha256(schemaObj);
        }
      } else {
        if (!cred.schema.url) {
          throw new Error(`credential ${cred.id}: referenced schema missing schema.url`);
        }
        if (!isHostAllowed(cred.schema.url)) {
          throw new Error(
            `credential ${cred.id}: schema URL host not on allowlist: ${cred.schema.url}`,
          );
        }
        const res = await fetchWithTimeoutAndRetry(cred.schema.url, fetchImpl);
        if (isYaml) {
          // YAML path: hash the raw bytes, then parse to JS for bundling.
          const buf = Buffer.from(await res.arrayBuffer());
          actualHash = sha256Bytes(buf);
          if (actualHash !== cred.schema.sha256) {
            err(
              `\nHASH MISMATCH for credential "${cred.id}":\n  expected: ${cred.schema.sha256}\n  actual:   ${actualHash}\n`,
            );
            throw new Error(`schema hash mismatch for ${cred.id}`);
          }
          try {
            schemaObj = YAML.parse(buf.toString("utf8"));
          } catch (e) {
            throw new Error(`credential ${cred.id}: fetched YAML is not parseable: ${e.message}`);
          }
          if (!schemaObj || typeof schemaObj !== "object") {
            throw new Error(`credential ${cred.id}: parsed YAML is not an object`);
          }
        } else {
          const text = await res.text();
          try {
            schemaObj = JSON.parse(text);
          } catch (e) {
            throw new Error(`credential ${cred.id}: fetched schema is not valid JSON: ${e.message}`);
          }
          actualHash = canonicalJsonSha256(schemaObj);
        }
        schemaUpstreamUrl = cred.schema.url;
      }

      // For JSON branches actualHash is canonical-JSON; for YAML it is
      // literal-bytes. Either way, the manifest entry was generated the same
      // way, so the comparison is apples-to-apples. Both YAML branches above
      // already compared inline before parsing; JSON branches compare here.
      if (!isYaml) {
        if (actualHash !== cred.schema.sha256) {
          err(
            `\nHASH MISMATCH for credential "${cred.id}":\n  expected: ${cred.schema.sha256}\n  actual:   ${actualHash}\n`,
          );
          throw new Error(`schema hash mismatch for ${cred.id}`);
        }
      }

      // Handle context (literal-bytes hash, not canonical)
      let contextUrl;
      if (cred.context) {
        if (typeof cred.context.sha256 !== "string") {
          throw new Error(`credential ${cred.id}: context missing sha256`);
        }
        let ctxBuf;
        let ctxUpstreamUrl;
        if (sourceKind === "defined" && cred.context.path) {
          const ctxLocal = join(extractedRoot, cred.context.path);
          if (!existsSync(ctxLocal)) {
            throw new Error(
              `credential ${cred.id}: context file missing in tarball: ${cred.context.path}`,
            );
          }
          ctxBuf = await readFile(ctxLocal);
          ctxUpstreamUrl =
            cred.context.upstreamUrl ??
            `https://raw.githubusercontent.com/${sources.repo}/${sources.commit}/${cred.context.path}`;
        } else if (cred.context.url) {
          if (!isHostAllowed(cred.context.url)) {
            throw new Error(
              `credential ${cred.id}: context URL host not on allowlist: ${cred.context.url}`,
            );
          }
          const res = await fetchWithTimeoutAndRetry(cred.context.url, fetchImpl);
          ctxBuf = Buffer.from(await res.arrayBuffer());
          ctxUpstreamUrl = cred.context.url;
        } else {
          throw new Error(`credential ${cred.id}: context entry has neither path nor url`);
        }
        // Context hashing matches Stream A's pinner convention:
        //   - defined contexts (files in the schemas tarball) → canonicalJsonSha256
        //     of the parsed JSON-LD, so repo edits that only reorder keys don't
        //     invalidate the pin.
        //   - referenced contexts (remote URLs) → sha256 of the raw bytes, so
        //     any upstream whitespace/byte change is detected.
        let ctxHash;
        if (sourceKind === "defined") {
          let ctxParsed;
          try {
            ctxParsed = JSON.parse(ctxBuf.toString("utf8"));
          } catch (e) {
            throw new Error(`credential ${cred.id}: context is not valid JSON: ${e.message}`);
          }
          ctxHash = canonicalJsonSha256(ctxParsed);
        } else {
          ctxHash = sha256Bytes(ctxBuf);
        }
        if (ctxHash !== cred.context.sha256) {
          err(
            `\nCONTEXT HASH MISMATCH for credential "${cred.id}":\n  expected: ${cred.context.sha256}\n  actual:   ${ctxHash}\n`,
          );
          throw new Error(`context hash mismatch for ${cred.id}`);
        }
        contextUrl = ctxUpstreamUrl;
        externalContexts.push({
          filename: `${idToFilename(cred.id)}.json`,
          bytes: ctxBuf,
        });
      }

      records.push({
        id: cred.id,
        constName: idToConst(cred.id),
        schema: schemaObj,
        version: cred.version ?? "1.0.0",
        lastUpdated: cred.lastUpdated ?? "2026-04-08T00:00:00Z",
        checksum: actualHash,
        contextUrl,
        source: {
          kind: sourceKind,
          upstreamUrl: schemaUpstreamUrl,
          upstreamOwner: cred.owner ?? "OpenCred",
          upstreamLicense: cred.license ?? "Apache-2.0",
        },
      });
    }

    // Write outputs
    const srcDir = join(opts.packageRoot, "src");
    await writeFile(join(srcDir, "schema-data.ts"), renderSchemaDataModule(records), "utf8");
    await writeFile(
      join(srcDir, "generated-registry.ts"),
      renderGeneratedRegistryModule(records),
      "utf8",
    );

    // External contexts → vc-core
    if (externalContexts.length > 0) {
      const ctxDir = join(opts.repoRoot, "packages", "vc-core", "src", "contexts", "external");
      await mkdir(ctxDir, { recursive: true });
      for (const ec of externalContexts) {
        await writeFile(join(ctxDir, ec.filename), ec.bytes);
      }
    }

    const definedCount = records.filter((r) => r.source.kind === "defined").length;
    const referencedCount = records.length - definedCount;
    log(
      `[fetch-and-embed-schemas] embedded ${records.length} credentials (${definedCount} defined, ${referencedCount} referenced), ${externalContexts.length} contexts; all hashes verified`,
    );

    return { records, externalContexts };
  } finally {
    await rm(extractDir, { recursive: true, force: true });
  }
}

/* ------------------------------------------------------------------ */
/* CLI                                                                */
/* ------------------------------------------------------------------ */

const isMain =
  import.meta.url.startsWith("file:") &&
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const here = dirname(fileURLToPath(import.meta.url));
  const packageRoot = resolve(here, "..");
  const repoRoot = resolve(packageRoot, "..", "..");
  run({
    packageRoot,
    repoRoot,
    localTarballPath: process.env.OPENCRED_SCHEMA_TARBALL || undefined,
  }).catch((e) => {
    console.error(`[fetch-and-embed-schemas] FAILED: ${e.message}`);
    process.exit(1);
  });
}
