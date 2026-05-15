import { defineConfig } from "tsup";

/**
 * Bundles the SDK into a single self-contained package:
 *
 *  - All `@opencred/*` workspace deps are inlined (`noExternal`), so the
 *    published package has zero workspace deps — a consumer's
 *    `npm install @opencred/verify` pulls in only the SDK + a handful of
 *    real npm deps (`jose`, `pdf-lib`, `@mosip/pixelpass`, `node-forge`).
 *  - Emits both ESM (`dist/index.js`) and CJS (`dist/index.cjs`) so the
 *    SDK works in modern ESM-first projects and legacy CJS projects alike.
 *  - Emits `.d.ts` types via tsup's built-in dts generation.
 *  - Source maps inlined for easier debugging downstream.
 */
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  target: "node20",
  // Inline the entire @opencred/* workspace; everything else stays as a real
  // npm dep in package.json so consumers' npm/pnpm/yarn dedupes them.
  noExternal: [/^@opencred\//],
});
