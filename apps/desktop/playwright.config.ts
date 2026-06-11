import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  retries: 0,
  workers: 1,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  // The Vite dev server must be started manually before running tests:
  //   cd apps/desktop && npx vite --port 5174
  // Set OPENCRED_DEV_URL env var if using a different port.
});
