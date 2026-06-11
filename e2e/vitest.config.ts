import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Container start + image pull + issuance round-trips are slow by
    // nature; these are integration tests, not unit tests.
    testTimeout: 120_000,
    hookTimeout: 180_000,
    // One file at a time — each spec manages its own containers/ports and
    // parallel files would race on the docker daemon for no wall-clock win.
    fileParallelism: false,
  },
});
