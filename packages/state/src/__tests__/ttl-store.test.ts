import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { TTLStore } from "../ttl-store.js";

describe("TTLStore", () => {
  let store: TTLStore<string>;

  beforeEach(() => {
    vi.useFakeTimers();
    store = new TTLStore<string>();
  });

  afterEach(() => {
    store.destroy();
    vi.useRealTimers();
  });

  describe("basic CRUD", () => {
    it("set and get a value", () => {
      store.set("key1", "value1");
      expect(store.get("key1")).toBe("value1");
    });

    it("returns undefined for missing keys", () => {
      expect(store.get("nonexistent")).toBeUndefined();
    });

    it("deletes a value", () => {
      store.set("key1", "value1");
      expect(store.delete("key1")).toBe(true);
      expect(store.get("key1")).toBeUndefined();
    });

    it("delete returns false for missing key", () => {
      expect(store.delete("nonexistent")).toBe(false);
    });

    it("has returns true for existing key", () => {
      store.set("key1", "value1");
      expect(store.has("key1")).toBe(true);
    });

    it("has returns false for missing key", () => {
      expect(store.has("nonexistent")).toBe(false);
    });

    it("size counts entries", () => {
      store.set("a", "1");
      store.set("b", "2");
      store.set("c", "3");
      expect(store.size).toBe(3);
    });

    it("clear removes all entries", () => {
      store.set("a", "1");
      store.set("b", "2");
      store.clear();
      expect(store.get("a")).toBeUndefined();
      expect(store.get("b")).toBeUndefined();
      expect(store.size).toBe(0);
    });

    it("overwrites existing key", () => {
      store.set("key1", "original");
      store.set("key1", "updated");
      expect(store.get("key1")).toBe("updated");
    });
  });

  describe("TTL expiry", () => {
    it("entry returns undefined after default TTL (4 hours)", () => {
      store.set("key1", "value1");
      expect(store.get("key1")).toBe("value1");

      vi.advanceTimersByTime(4 * 60 * 60 * 1000);
      expect(store.get("key1")).toBeUndefined();
    });

    it("entry is accessible just before TTL expiry", () => {
      store.set("key1", "value1");

      vi.advanceTimersByTime(4 * 60 * 60 * 1000 - 1);
      expect(store.get("key1")).toBe("value1");
    });

    it("custom TTL per entry", () => {
      store.set("short", "expires-fast", 1000);
      store.set("long", "expires-slow", 10000);

      vi.advanceTimersByTime(1000);
      expect(store.get("short")).toBeUndefined();
      expect(store.get("long")).toBe("expires-slow");

      vi.advanceTimersByTime(9000);
      expect(store.get("long")).toBeUndefined();
    });

    it("has respects TTL", () => {
      store.set("key1", "value1", 500);
      expect(store.has("key1")).toBe(true);

      vi.advanceTimersByTime(500);
      expect(store.has("key1")).toBe(false);
    });
  });

  describe("lazy eviction", () => {
    it("expired entry is cleaned up on get", () => {
      store.set("key1", "value1", 100);
      vi.advanceTimersByTime(100);

      expect(store.get("key1")).toBeUndefined();
      expect(store.get("key1")).toBeUndefined();
    });
  });

  describe("periodic sweep", () => {
    it("cleans expired entries on sweep interval", () => {
      const sweepStore = new TTLStore<string>(1000, 500);
      sweepStore.set("a", "1");
      sweepStore.set("b", "2");

      vi.advanceTimersByTime(1000);
      vi.advanceTimersByTime(500);

      expect(sweepStore.get("a")).toBeUndefined();
      expect(sweepStore.get("b")).toBeUndefined();

      sweepStore.destroy();
    });
  });

  describe("size counts non-expired entries", () => {
    it("excludes expired entries from size", () => {
      store.set("short", "val", 100);
      store.set("long", "val", 10000);
      expect(store.size).toBe(2);

      vi.advanceTimersByTime(100);
      expect(store.size).toBe(1);
    });
  });

  describe("destroy", () => {
    it("clears all entries and stops the sweep timer", () => {
      store.set("a", "1");
      store.set("b", "2");
      store.destroy();
      expect(store.size).toBe(0);
      expect(store.get("a")).toBeUndefined();
    });
  });

  describe("custom default TTL", () => {
    it("uses constructor-provided default TTL", () => {
      const customStore = new TTLStore<string>(2000);
      customStore.set("key", "value");

      vi.advanceTimersByTime(1999);
      expect(customStore.get("key")).toBe("value");

      vi.advanceTimersByTime(1);
      expect(customStore.get("key")).toBeUndefined();

      customStore.destroy();
    });
  });
});
