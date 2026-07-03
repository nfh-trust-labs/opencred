import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { OPENCRED_ELECTRICITY_V1_CONTEXT } from "../types.js";

/**
 * Guard against a known footgun: the OpenCred-defined context URLs in
 * `types.ts` embed the `opencred-vc-schemas` commit SHA
 * (`OPENCRED_SCHEMAS_SHA`), and `document-loader.ts`'s BUNDLED_CONTEXTS map is
 * keyed by those URLs. `schema-engine`'s `generated-registry.ts` embeds the
 * SAME pin in the `contextUrl` that lands in issued credentials. If the pin in
 * `schema-engine/scripts/schema-sources.json` is bumped but the `types.ts`
 * constant is not, issued data-integrity credentials carry a context URL the
 * bundled loader can't resolve → `ContextNotFoundError`.
 * `fetch-and-embed-schemas.mjs` does NOT update the `types.ts` constant, so
 * this test is the mechanical sync check until that is auto-generated.
 */
describe("schema pin sync (types.ts <-> schema-sources.json)", () => {
  it("OpenCred context URLs embed the same commit SHA as the schema pin", () => {
    const sourcesPath = fileURLToPath(
      new URL("../../../schema-engine/scripts/schema-sources.json", import.meta.url),
    );
    const pinnedCommit = JSON.parse(readFileSync(sourcesPath, "utf8")).commit as string;
    expect(pinnedCommit).toMatch(/^[0-9a-f]{40}$/);

    // Extract the SHA embedded in an OpenCred-defined context URL.
    const m = OPENCRED_ELECTRICITY_V1_CONTEXT.match(/opencred-vc-schemas\/([0-9a-f]{40})\//);
    expect(m, `could not extract SHA from ${OPENCRED_ELECTRICITY_V1_CONTEXT}`).not.toBeNull();
    expect(m![1]).toBe(pinnedCommit);
  });
});
