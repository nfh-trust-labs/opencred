/**
 * bundle-main.mjs — Bundle Electron main process and preload with esbuild.
 *
 * WHY: pnpm uses symlinks and a virtual store for node_modules. electron-builder
 * can't follow these symlinks outside the app directory. Previously we used a
 * 300-line flatten-deps.cjs script that resolved symlinks, hoisted transitive
 * deps, and registered them in package.json — but it kept missing edge cases
 * (nested transitive deps, version conflicts, etc.), causing MODULE_NOT_FOUND
 * crashes in the packaged app.
 *
 * The fix: bundle ALL JavaScript dependencies into single files with esbuild.
 * The packaged app no longer needs node_modules for JS code — only for native
 * .node addons (pkcs11js). This eliminates the entire class of pnpm ↔
 * electron-builder compatibility issues.
 *
 * WHAT THIS BUNDLES:
 *   Main process:  src/main/index.ts → dist/main/main/index.js  (ESM)
 *   Preload:       src/main/preload.ts → dist/preload/main/preload.cjs (CJS)
 *
 * WHAT STAYS EXTERNAL:
 *   - electron (provided by Electron at runtime)
 *   - pkcs11js (native .node addon, stays in node_modules)
 *   - *.node files (native addons, handled by plugin)
 */

import * as esbuild from "esbuild";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const desktopRoot = path.resolve(__dirname, "..");

/**
 * Plugin: handle native .node addon requires.
 *
 * When esbuild encounters require("path/to/something.node"), this plugin:
 * 1. Resolves the actual .node file on disk
 * 2. Copies it to dist/native/ alongside the bundle
 * 3. Rewrites the require to "./native/filename.node" (relative to bundle)
 *
 * If the .node file doesn't exist (e.g., macOS addon on Linux), the copy
 * is skipped. The runtime code already has try/catch for this case.
 */
function nativeAddonPlugin(outDir) {
  const nativeDir = path.join(outDir, "native");
  return {
    name: "native-addon",
    setup(build) {
      // Match require calls ending in .node
      build.onResolve({ filter: /\.node$/ }, (args) => {
        // Resolve relative to the file that imports it
        const resolveFrom = args.resolveDir || path.dirname(args.importer);
        const resolved = path.resolve(resolveFrom, args.path);
        const filename = path.basename(resolved);

        // Copy the .node file if it exists
        if (fs.existsSync(resolved)) {
          fs.mkdirSync(nativeDir, { recursive: true });
          fs.copyFileSync(resolved, path.join(nativeDir, filename));
          console.log(`  [native] Copied ${filename}`);
        } else {
          console.log(`  [native] ${filename} not found (platform-specific, skipped)`);
        }

        // Rewrite require to point to the copied file
        return { path: `./native/${filename}`, external: true };
      });
    },
  };
}

/**
 * Plugin: handle createRequire patterns.
 *
 * Several modules use createRequire(import.meta.url) to load CJS modules
 * from ESM code. esbuild can't trace through the variable assignment, but
 * the actual require() calls use static string arguments. This plugin
 * rewrites them to standard require() that esbuild can resolve.
 */
function createRequirePlugin() {
  return {
    name: "create-require-rewrite",
    setup(build) {
      // Process .ts and .js files that contain createRequire
      build.onLoad({ filter: /\.(ts|js|mts|mjs)$/ }, async (args) => {
        const source = await fs.promises.readFile(args.path, "utf-8");
        if (!source.includes("createRequire")) return undefined;

        // Remove the createRequire import and variable assignment
        let rewritten = source
          // Remove: import { createRequire } from "node:module";
          .replace(/import\s*\{[^}]*createRequire[^}]*\}\s*from\s*["']node:module["'];?\s*\n?/g, "")
          // Remove: const require = createRequire(import.meta.url);
          // Also handles: const nodeRequire = createRequire(import.meta.url);
          .replace(/(?:const|let|var)\s+\w+\s*=\s*createRequire\([^)]*\);?\s*\n?/g, "");

        // The remaining require() calls are now plain require() — esbuild
        // will resolve them normally since platform is 'node'.

        return { contents: rewritten, loader: args.path.endsWith(".ts") ? "ts" : "js" };
      });
    },
  };
}

// ---------------------------------------------------------------------------
// Clean old tsc output from dist/main/ and dist/preload/ — esbuild replaces
// them with single-file bundles. Stale tsc files would confuse electron-builder
// (it follows their import paths into workspace packages outside apps/desktop/).
// ---------------------------------------------------------------------------

const distDir = path.join(desktopRoot, "dist");
for (const subdir of ["main", "preload"]) {
  const dir = path.join(distDir, subdir);
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true });
    console.log(`[bundle] Cleaned dist/${subdir}/`);
  }
}

// ---------------------------------------------------------------------------
// Bundle main process
// ---------------------------------------------------------------------------

const mainOutDir = path.join(distDir, "main", "main");

console.log("[bundle] Bundling main process...");
const mainResult = await esbuild.build({
  entryPoints: [path.join(desktopRoot, "src", "main", "index.ts")],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  outfile: path.join(mainOutDir, "index.js"),
  // Keep import.meta.url working (esbuild preserves it in ESM output)
  // __dirname is derived from import.meta.url in the source, so it points
  // to dist/main/main/ — exactly where tsc would have put the file.
  external: ["electron", "pkcs11js"],
  plugins: [nativeAddonPlugin(mainOutDir), createRequirePlugin()],
  // Tree-shake unused code
  treeShaking: true,
  // Produce readable output for debugging
  minify: false,
  // Generate source maps for stack traces
  sourcemap: true,
  // Banner: create a require() function in ESM context so external CJS
  // packages (electron, pkcs11js) can be loaded via require().
  banner: {
    js: [
      "// Bundled by esbuild — all JS deps inlined, no node_modules needed",
      "import { createRequire as __bundleCreateRequire } from 'node:module';",
      "const require = __bundleCreateRequire(import.meta.url);",
    ].join("\n"),
  },
  // Resolve workspace packages through node_modules symlinks
  resolveExtensions: [".ts", ".tsx", ".js", ".jsx", ".json"],
  // Log level
  logLevel: "warning",
  // Handle JSON imports
  loader: {
    ".json": "json",
  },
  metafile: true,
});

// Report bundle size
const mainMeta = mainResult.metafile;
const mainOutput = Object.values(mainMeta.outputs).find((o) => o.entryPoint);
console.log(
  `[bundle] Main process: ${(mainOutput?.bytes || 0 / 1024).toFixed(0)} KB ` +
    `(${Object.keys(mainMeta.inputs).length} modules)`
);

// ---------------------------------------------------------------------------
// Bundle preload script
// ---------------------------------------------------------------------------

const preloadOutDir = path.join(distDir, "preload", "main");

console.log("[bundle] Bundling preload script...");
await esbuild.build({
  entryPoints: [path.join(desktopRoot, "src", "main", "preload.ts")],
  bundle: true,
  platform: "node",
  target: "node20",
  // Preload MUST be CommonJS for Electron
  format: "cjs",
  outfile: path.join(preloadOutDir, "preload.cjs"),
  external: ["electron"],
  plugins: [createRequirePlugin()],
  treeShaking: true,
  minify: false,
  sourcemap: true,
  resolveExtensions: [".ts", ".tsx", ".js", ".jsx", ".json"],
  logLevel: "warning",
  loader: {
    ".json": "json",
  },
});

console.log("[bundle] Preload script bundled");

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log("[bundle] Done. Native addons that need to stay in node_modules: pkcs11js");
