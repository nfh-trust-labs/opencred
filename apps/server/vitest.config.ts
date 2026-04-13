import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/__tests__/**/*.test.ts"],
    testTimeout: 30000,
    alias: {
      // pkcs11js requires a native binary that may not be available in test env.
      // The server doesn't use PKCS#11 — stub it out.
      pkcs11js: new URL("src/__tests__/stubs/pkcs11js.ts", import.meta.url).pathname,
      // @mosip/pixelpass may not install cleanly on all platforms — stub it
      // so that tests importing the app (which transitively loads qr-generator)
      // do not fail at module resolution time.
      "@mosip/pixelpass": new URL("src/__tests__/stubs/pixelpass.ts", import.meta.url).pathname,
    },
  },
});
