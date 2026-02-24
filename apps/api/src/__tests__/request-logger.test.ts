import { describe, it, expect } from "vitest";
import { createApp } from "../app.js";
import { makeTestConfig, makeTestLogger } from "./helpers.js";

describe("Request logger middleware", () => {
  it("adds X-Request-Id header to response", async () => {
    const { app } = createApp({ config: makeTestConfig(), logger: makeTestLogger() });
    const res = await app.request("/health");
    expect(res.headers.get("x-request-id")).toBeDefined();
    expect(res.headers.get("x-request-id")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it("echoes back client-provided X-Request-Id", async () => {
    const { app } = createApp({ config: makeTestConfig(), logger: makeTestLogger() });
    const requestId = "custom-request-id-123";
    const res = await app.request("/health", {
      headers: { "x-request-id": requestId },
    });
    expect(res.headers.get("x-request-id")).toBe(requestId);
  });
});
