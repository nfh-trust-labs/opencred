import { describe, it, expect } from "vitest";
import { createApp } from "../app.js";
import { makeTestConfig, makeTestLogger } from "./helpers.js";

describe("GET /health", () => {
  it("returns 200 with status ok", async () => {
    const { app } = createApp({ config: makeTestConfig(), logger: makeTestLogger() });
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; timestamp: string };
    expect(body.status).toBe("ok");
    expect(body.timestamp).toBeDefined();
  });

  it("returns a valid ISO timestamp", async () => {
    const { app } = createApp({ config: makeTestConfig(), logger: makeTestLogger() });
    const res = await app.request("/health");
    const body = (await res.json()) as { timestamp: string };
    const parsed = new Date(body.timestamp);
    expect(parsed.toISOString()).toBe(body.timestamp);
  });
});
