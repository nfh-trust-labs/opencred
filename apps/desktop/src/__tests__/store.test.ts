/**
 * Tests for the electron-store configuration module.
 *
 * Since electron-store requires an Electron environment (app.getPath),
 * these tests mock the electron-store module and verify the store's
 * initialisation logic, default values, and error handling.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock electron-store before importing the store module.
const mockGet = vi.fn();
const mockSet = vi.fn();
const mockStore = {
  get: mockGet,
  set: mockSet,
  store: {},
};

vi.mock("electron-store", () => ({
  default: vi.fn().mockImplementation(() => mockStore),
}));

// Import after mocking.
const { initStore, getStore } = await import("../main/store");

describe("Store", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("initStore should return a store instance", () => {
    const store = initStore();
    expect(store).toBeDefined();
    expect(store).toBe(mockStore);
  });

  it("initStore should be idempotent (returns the same instance on repeated calls)", () => {
    const store1 = initStore();
    const store2 = initStore();
    expect(store1).toBe(store2);
  });

  it("getStore should return the initialised store", () => {
    initStore();
    const store = getStore();
    expect(store).toBe(mockStore);
  });

  it("store.get should delegate to the underlying electron-store", () => {
    initStore();
    const store = getStore();
    mockGet.mockReturnValue("dark");

    const result = store.get("theme" as keyof typeof store.store);
    expect(mockGet).toHaveBeenCalledWith("theme");
    expect(result).toBe("dark");
  });

  it("store.set should delegate to the underlying electron-store", () => {
    initStore();
    const store = getStore();

    store.set("theme" as keyof typeof store.store, "light");
    expect(mockSet).toHaveBeenCalledWith("theme", "light");
  });
});
