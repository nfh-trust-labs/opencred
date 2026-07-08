import { defineConfig } from "vitest/config";

export default defineConfig({
  // Renderer components use the automatic JSX runtime (no `import React`), so
  // tell esbuild to transform `.tsx` the same way. Only affects files that
  // contain JSX; the existing node-environment `.test.ts` files are untouched.
  esbuild: { jsx: "automatic", jsxImportSource: "react" },
  test: {
    globals: true,
    // Default environment is node; render tests opt into a DOM per-file via
    // `// @vitest-environment happy-dom`.
    environment: "node",
    include: ["src/__tests__/**/*.test.{ts,tsx}"],
    exclude: ["node_modules", "dist", "out"],
  },
});
