/**
 * Generate a P-256 demo issuer JWK and write it to sample-keys/.
 *
 * Usage:
 *   npx tsx demos/generate-demo-jwk.ts
 *
 * Called automatically by demos/setup-demo.sh, but can also be run standalone.
 *
 * WARNING: This JWK is for demonstration purposes ONLY.
 * Do NOT use demo material for production credential issuance.
 */
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outputDir = resolve(__dirname, "sample-keys");
const outputPath = resolve(outputDir, "demo-issuer.jwk");

if (existsSync(outputPath)) {
  console.log(`  JWK already exists at ${outputPath} — skipping generation.`);
  console.log("  Delete the file and re-run to regenerate.");
  process.exit(0);
}

const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

const jwk = privateKey.export({ format: "jwk" });

mkdirSync(outputDir, { recursive: true });
writeFileSync(outputPath, JSON.stringify(jwk, null, 2) + "\n", "utf-8");

console.log(`  Demo issuer JWK (P-256) written to ${outputPath}`);
