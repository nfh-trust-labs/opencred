/**
 * Tests for the DeDi client singleton.
 */

import { describe, it, expect, afterEach } from "vitest";
import { getDeDiClient, setDeDiClient, resetDeDiClient } from "../dedi-singleton.js";
import type { DeDiClient } from "@opencred/dedi-client";

afterEach(() => {
  resetDeDiClient();
});

describe("DeDi singleton", () => {
  it("returns null when no client is set", () => {
    expect(getDeDiClient()).toBeNull();
  });

  it("returns the client after setDeDiClient()", () => {
    const mock = { fake: true } as unknown as DeDiClient;
    setDeDiClient(mock);
    expect(getDeDiClient()).toBe(mock);
  });

  it("returns null after resetDeDiClient()", () => {
    const mock = { fake: true } as unknown as DeDiClient;
    setDeDiClient(mock);
    expect(getDeDiClient()).toBe(mock);

    resetDeDiClient();
    expect(getDeDiClient()).toBeNull();
  });

  it("overwrites a previously set client", () => {
    const first = { id: 1 } as unknown as DeDiClient;
    const second = { id: 2 } as unknown as DeDiClient;

    setDeDiClient(first);
    expect(getDeDiClient()).toBe(first);

    setDeDiClient(second);
    expect(getDeDiClient()).toBe(second);
  });
});
