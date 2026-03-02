import { describe, it, expect } from "vitest";
import { createApp } from "../app.js";
import { makeTestConfig, makeTestLogger } from "./helpers.js";

describe("CORS", () => {
  it("includes CORS headers for allowed origin", async () => {
    const { app } = createApp({ config: makeTestConfig(), logger: makeTestLogger() });
    const res = await app.request("/health", {
      headers: { Origin: "http://localhost:5173" },
    });
    expect(res.headers.get("access-control-allow-origin")).toBe("http://localhost:5173");
    expect(res.headers.get("access-control-allow-credentials")).toBe("true");
  });

  it("does not include CORS headers for disallowed origin", async () => {
    const { app } = createApp({ config: makeTestConfig(), logger: makeTestLogger() });
    const res = await app.request("/health", {
      headers: { Origin: "http://evil.example.com" },
    });
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("handles preflight OPTIONS request", async () => {
    const { app } = createApp({ config: makeTestConfig(), logger: makeTestLogger() });
    const res = await app.request("/health", {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type, Authorization",
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("http://localhost:5173");
    expect(res.headers.get("access-control-allow-methods")).toContain("POST");
    expect(res.headers.get("access-control-allow-headers")).toContain("Authorization");
  });

  it("exposes rate limit and request ID headers", async () => {
    const { app } = createApp({ config: makeTestConfig(), logger: makeTestLogger() });
    const res = await app.request("/health", {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:5173",
        "Access-Control-Request-Method": "GET",
      },
    });
    const exposed = res.headers.get("access-control-expose-headers") ?? "";
    expect(exposed).toContain("X-Request-Id");
    expect(exposed).toContain("X-RateLimit-Limit");
  });

  it("only allows GET, POST, and OPTIONS methods (#144)", async () => {
    const { app } = createApp({ config: makeTestConfig(), logger: makeTestLogger() });
    const res = await app.request("/health", {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:5173",
        "Access-Control-Request-Method": "GET",
      },
    });
    const methods = res.headers.get("access-control-allow-methods") ?? "";
    expect(methods).toContain("GET");
    expect(methods).toContain("POST");
    expect(methods).not.toContain("PUT");
    expect(methods).not.toContain("DELETE");
  });

  it("respects custom CORS origin from config", async () => {
    const { app } = createApp({
      config: makeTestConfig({ CORS_ORIGIN: "https://app.opencred.io" }),
      logger: makeTestLogger(),
    });
    const res = await app.request("/health", {
      headers: { Origin: "https://app.opencred.io" },
    });
    expect(res.headers.get("access-control-allow-origin")).toBe("https://app.opencred.io");
  });
});
