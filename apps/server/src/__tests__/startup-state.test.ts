/**
 * Tests for the startup-state singleton (didAutoPublished surface).
 */

import { describe, it, expect, afterEach } from "vitest";
import {
  getDidAutoPublishedAtStartup,
  setDidAutoPublishedAtStartup,
  resetStartupState,
} from "../startup-state.js";

afterEach(() => {
  resetStartupState();
});

describe("startup-state", () => {
  it("defaults to false before any setter call", () => {
    expect(getDidAutoPublishedAtStartup()).toBe(false);
  });

  it("returns true after setDidAutoPublishedAtStartup(true)", () => {
    setDidAutoPublishedAtStartup(true);
    expect(getDidAutoPublishedAtStartup()).toBe(true);
  });

  it("can be flipped back to false", () => {
    setDidAutoPublishedAtStartup(true);
    expect(getDidAutoPublishedAtStartup()).toBe(true);
    setDidAutoPublishedAtStartup(false);
    expect(getDidAutoPublishedAtStartup()).toBe(false);
  });

  it("resetStartupState() returns to default", () => {
    setDidAutoPublishedAtStartup(true);
    resetStartupState();
    expect(getDidAutoPublishedAtStartup()).toBe(false);
  });
});
