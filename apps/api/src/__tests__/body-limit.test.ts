import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { bodyLimitMiddleware } from "../middleware/body-limit.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

interface ErrorBody {
  error: { code: string; message: string };
}

const logger = makeTestLogger();

function createTestApp(maxSize: number) {
  const app = new Hono();
  app.use("/*", bodyLimitMiddleware({ maxSize }));
  app.post("/upload", async (c) => {
    const body = await c.req.text();
    return c.json({ size: body.length });
  });
  app.get("/get", (c) => c.json({ ok: true }));
  app.onError(errorHandler(logger));
  return app;
}

/**
 * Helper to create a ReadableStream from a string, simulating chunked
 * transfer (no Content-Length header).
 */
function chunkedBody(data: string): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(data);
  return new ReadableStream({
    start(controller) {
      const mid = Math.ceil(bytes.length / 2);
      controller.enqueue(bytes.slice(0, mid));
      controller.enqueue(bytes.slice(mid));
      controller.close();
    },
  });
}

describe("Body limit middleware (#174)", () => {
  it("allows requests within the size limit", async () => {
    const app = createTestApp(1024);
    const res = await app.request("/upload", {
      method: "POST",
      headers: { "content-length": "100", "content-type": "application/json" },
      body: JSON.stringify({ data: "x".repeat(80) }),
    });
    expect(res.status).toBe(200);
  });

  it("rejects requests exceeding the size limit", async () => {
    const app = createTestApp(100);
    const res = await app.request("/upload", {
      method: "POST",
      headers: { "content-length": "200", "content-type": "application/json" },
      body: JSON.stringify({ data: "x".repeat(180) }),
    });
    expect(res.status).toBe(413);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("PAYLOAD_TOO_LARGE");
  });

  it("allows requests without Content-Length header", async () => {
    const app = createTestApp(100);
    const res = await app.request("/get");
    expect(res.status).toBe(200);
  });

  it("allows requests with Content-Length at exactly the limit", async () => {
    const app = createTestApp(100);
    const res = await app.request("/upload", {
      method: "POST",
      headers: { "content-length": "100", "content-type": "application/json" },
      body: JSON.stringify({ data: "x".repeat(80) }),
    });
    expect(res.status).toBe(200);
  });

  it("rejects requests with Content-Length just over the limit", async () => {
    const app = createTestApp(100);
    const res = await app.request("/upload", {
      method: "POST",
      headers: { "content-length": "101", "content-type": "application/json" },
      body: "x".repeat(101),
    });
    expect(res.status).toBe(413);
  });

  it("uses default 1 MiB limit when no options provided", async () => {
    const app = new Hono();
    app.use("/*", bodyLimitMiddleware());
    app.post("/upload", async (c) => c.json({ ok: true }));
    app.onError(errorHandler(logger));

    const res = await app.request("/upload", {
      method: "POST",
      headers: { "content-length": String(1024 * 1024), "content-type": "application/json" },
      body: "x",
    });
    expect(res.status).toBe(200);

    const res2 = await app.request("/upload", {
      method: "POST",
      headers: { "content-length": String(1024 * 1024 + 1), "content-type": "application/json" },
      body: "x",
    });
    expect(res2.status).toBe(413);
  });
});

describe("Body limit — chunked transfer bypass (#125)", () => {
  it("rejects chunked POST exceeding the limit (no Content-Length)", async () => {
    const app = createTestApp(50);
    const oversized = "x".repeat(100);
    const req = new Request("http://localhost/upload", {
      method: "POST",
      body: chunkedBody(oversized),
      headers: { "content-type": "application/octet-stream" },
      duplex: "half",
    });
    req.headers.delete("content-length");

    const res = await app.request(req);
    expect(res.status).toBe(413);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("PAYLOAD_TOO_LARGE");
  });

  it("allows chunked POST within the limit (no Content-Length)", async () => {
    const app = createTestApp(200);
    const payload = "x".repeat(50);
    const req = new Request("http://localhost/upload", {
      method: "POST",
      body: chunkedBody(payload),
      headers: { "content-type": "application/octet-stream" },
      duplex: "half",
    });
    req.headers.delete("content-length");

    const res = await app.request(req);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { size: number };
    expect(body.size).toBe(50);
  });

  it("passes GET requests through without stream reading", async () => {
    const app = createTestApp(10);
    const res = await app.request("/get");
    expect(res.status).toBe(200);
  });
});
