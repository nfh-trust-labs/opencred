import { header, success, error, separator } from "./helpers.js";

interface DemoModule {
  main: () => Promise<void>;
}

const demos = [
  { name: "01 — Key Generation", file: "./01-key-generation.js" },
  { name: "02 — Credential Issuance", file: "./02-credential-issuance.js" },
  { name: "03 — Interface Signing", file: "./03-interface-signing.js" },
  { name: "04 — Delegation Lifecycle", file: "./04-delegation-lifecycle.js" },
  { name: "05 — Verification", file: "./05-verification.js" },
  { name: "06 — Schema Validation", file: "./06-schema-validation.js" },
  { name: "07 — Revocation Hashing", file: "./07-revocation.js" },
  { name: "08 — Auth Tokens", file: "./08-auth-tokens.js" },
  { name: "09 — All Signers", file: "./09-all-signers.js" },
];

async function runAll(): Promise<void> {
  header("OpenCred Demo Suite");
  console.log(`  Running ${demos.length} demos...\n`);

  const results: { name: string; passed: boolean; error?: string }[] = [];

  for (const demo of demos) {
    try {
      const mod = (await import(demo.file)) as DemoModule;
      await mod.main();
      results.push({ name: demo.name, passed: true });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      error(`${demo.name} failed: ${msg}`);
      results.push({ name: demo.name, passed: false, error: msg });
    }
  }

  separator();
  header("Summary");

  let passed = 0;
  let failed = 0;
  for (const r of results) {
    if (r.passed) {
      success(r.name);
      passed++;
    } else {
      error(`${r.name}: ${r.error}`);
      failed++;
    }
  }

  separator();
  console.log(`  ${passed} passed, ${failed} failed, ${demos.length} total\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runAll().catch((e) => {
  console.error(e);
  process.exit(1);
});
