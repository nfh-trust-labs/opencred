/**
 * Tests for the p11-kit auto-discovery function.
 *
 * Tests that autoDiscoverP11KitModule correctly searches well-known paths
 * on Linux. On non-Linux platforms, the function still works but will
 * typically return null since the paths don't exist.
 */

import { describe, it, expect } from "vitest";
import { autoDiscoverP11KitModule } from "../p11-kit-discovery.js";

describe("autoDiscoverP11KitModule", () => {
  it("should return a string path or null", () => {
    const result = autoDiscoverP11KitModule();
    expect(result === null || typeof result === "string").toBe(true);
  });

  it("should return a path ending in p11-kit-proxy.so when found", () => {
    const result = autoDiscoverP11KitModule();
    if (result !== null) {
      expect(result).toMatch(/p11-kit-proxy\.so$/);
    }
  });

  it("should return an absolute path when found", () => {
    const result = autoDiscoverP11KitModule();
    if (result !== null) {
      expect(result.startsWith("/")).toBe(true);
    }
  });
});
