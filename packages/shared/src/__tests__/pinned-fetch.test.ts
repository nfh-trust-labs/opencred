/**
 * Unit tests for `fetchWithPinnedIp` — the DNS-rebinding-safe HTTPS GET.
 *
 * These tests mock `node:https` and assert the two properties that make the
 * helper rebinding-safe AND TLS-correct:
 *
 *  1. The socket-level `lookup` is overridden to return ONLY the pinned,
 *     pre-validated addresses — DNS is never consulted between validation
 *     and connect.
 *  2. The URL keeps the original hostname (it is passed unmodified to
 *     `https.request`), so TLS SNI + certificate validation run against the
 *     hostname. (Putting the IP in the URL with a `Host` header fails with
 *     ERR_TLS_CERT_ALTNAME_INVALID — verified empirically against live
 *     hosts.)
 *
 * A third property — every request uses a fresh non-keep-alive Agent so a
 * pooled socket can never bypass the pin — is asserted via the Agent
 * constructor options.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Readable } from "node:stream";
import { EventEmitter } from "node:events";
import type { LookupFunction } from "node:net";

interface CapturedRequest {
  url: URL;
  options: Record<string, unknown>;
  body?: Buffer;
}

const captured: CapturedRequest[] = [];
const agentOptions: Array<Record<string, unknown>> = [];

/** Configurable fake response for the next https.request call. */
let nextResponse: {
  statusCode: number;
  statusMessage?: string;
  headers?: Record<string, string | string[]>;
  body?: string;
  error?: Error;
} = { statusCode: 200 };

vi.mock("node:https", () => ({
  Agent: vi.fn().mockImplementation((opts: Record<string, unknown>) => {
    agentOptions.push(opts);
    return { __isMockAgent: true, options: opts };
  }),
  request: vi.fn(
    (
      url: URL,
      options: Record<string, unknown>,
      callback: (res: unknown) => void,
    ): EventEmitter & { end: (chunk?: Buffer) => void } => {
      const entry: CapturedRequest = { url, options };
      captured.push(entry);
      const req = new EventEmitter() as EventEmitter & { end: (chunk?: Buffer) => void };
      req.end = (chunk?: Buffer) => {
        if (chunk !== undefined) entry.body = chunk;
        if (nextResponse.error) {
          queueMicrotask(() => req.emit("error", nextResponse.error));
          return;
        }
        const res = Readable.from([Buffer.from(nextResponse.body ?? "")]) as Readable &
          Record<string, unknown>;
        res["statusCode"] = nextResponse.statusCode;
        res["statusMessage"] = nextResponse.statusMessage ?? "";
        res["headers"] = nextResponse.headers ?? {};
        queueMicrotask(() => {
          callback(res);
        });
      };
      return req;
    },
  ),
}));

const { fetchWithPinnedIp } = await import("../pinned-fetch.js");

describe("fetchWithPinnedIp", () => {
  beforeEach(() => {
    captured.length = 0;
    agentOptions.length = 0;
    nextResponse = { statusCode: 200, body: "{}" };
  });

  it("rejects non-HTTPS URLs before any request is made", async () => {
    await expect(fetchWithPinnedIp("http://example.com/", ["93.184.216.34"])).rejects.toThrow(
      "requires an https: URL",
    );
    expect(captured).toHaveLength(0);
  });

  it("rejects an empty pinned-address list", async () => {
    await expect(fetchWithPinnedIp("https://example.com/", [])).rejects.toThrow(
      "at least one valid pinned IP",
    );
    expect(captured).toHaveLength(0);
  });

  it("rejects a pinned list containing only non-IP values (hostnames cannot be pinned)", async () => {
    await expect(
      fetchWithPinnedIp("https://example.com/", ["still-a-hostname.example.com"]),
    ).rejects.toThrow("at least one valid pinned IP");
    expect(captured).toHaveLength(0);
  });

  it("keeps the original hostname in the request URL (TLS validates against the hostname)", async () => {
    await fetchWithPinnedIp("https://issuer.example.com/.well-known/did.json", ["93.184.216.34"]);

    expect(captured).toHaveLength(1);
    expect(captured[0].url.hostname).toBe("issuer.example.com");
    // No Host-header override — the hostname is authoritative.
    expect(captured[0].options["headers"]).toBeUndefined();
  });

  it("uses a fresh non-keep-alive Agent so pooled sockets can never bypass the pin", async () => {
    await fetchWithPinnedIp("https://example.com/", ["93.184.216.34"]);
    await fetchWithPinnedIp("https://example.com/", ["1.1.1.1"]);

    expect(agentOptions).toHaveLength(2);
    for (const opts of agentOptions) {
      expect(opts["keepAlive"]).toBe(false);
      expect(typeof opts["lookup"]).toBe("function");
    }
    expect(captured[0].options["agent"]).not.toBe(captured[1].options["agent"]);
  });

  it("overrides lookup to return ONLY the pinned addresses — DNS is never re-consulted", async () => {
    await fetchWithPinnedIp("https://rebind.example.com/", [
      "93.184.216.34",
      "2606:2800:220:1:248:1893:25c8:1946",
    ]);

    const lookup = agentOptions[0]["lookup"] as LookupFunction;

    // Happy-eyeballs path (`all: true`) gets every pinned address...
    const allResult = await new Promise((resolve, reject) => {
      lookup("rebind.example.com", { all: true }, (err, addresses) => {
        if (err) reject(err);
        else resolve(addresses);
      });
    });
    expect(allResult).toEqual([
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
    ]);

    // ...and the legacy single-address path gets the first one.
    const single = await new Promise((resolve, reject) => {
      lookup("rebind.example.com", {}, (err, address, family) => {
        if (err) reject(err);
        else resolve({ address, family });
      });
    });
    expect(single).toEqual({ address: "93.184.216.34", family: 4 });
  });

  it("returns a standard Response with status, statusText, headers, and body", async () => {
    nextResponse = {
      statusCode: 404,
      statusMessage: "Not Found",
      headers: { "content-type": "application/json", "x-multi": ["a", "b"] },
      body: '{"error":"missing"}',
    };

    const response = await fetchWithPinnedIp("https://example.com/nope", ["93.184.216.34"]);

    expect(response.ok).toBe(false);
    expect(response.status).toBe(404);
    expect(response.statusText).toBe("Not Found");
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("x-multi")).toBe("a, b");
    expect(await response.json()).toEqual({ error: "missing" });
  });

  it("forwards request headers", async () => {
    await fetchWithPinnedIp("https://example.com/", ["93.184.216.34"], {
      headers: { Accept: "application/did+ld+json" },
    });

    expect(captured[0].options["headers"]).toEqual({ Accept: "application/did+ld+json" });
  });

  it("produces a null-body Response for 204", async () => {
    nextResponse = { statusCode: 204 };

    const response = await fetchWithPinnedIp("https://example.com/", ["93.184.216.34"]);

    expect(response.status).toBe(204);
    expect(response.body).toBeNull();
  });

  it("defaults to GET with no body", async () => {
    await fetchWithPinnedIp("https://example.com/", ["93.184.216.34"]);

    expect(captured[0].options["method"]).toBe("GET");
    expect(captured[0].body).toBeUndefined();
    // No body ⇒ no Content-Length is invented.
    expect(captured[0].options["headers"]).toBeUndefined();
  });

  it("sends a POST body with an accurate Content-Length", async () => {
    const body = JSON.stringify({ jobId: "job-1", status: "completed" });

    await fetchWithPinnedIp("https://hooks.example.com/webhook", ["93.184.216.34"], {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-OpenCred-Event": "batch.completed" },
      body,
    });

    expect(captured[0].options["method"]).toBe("POST");
    expect(captured[0].body?.toString("utf8")).toBe(body);
    const headers = captured[0].options["headers"] as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers["X-OpenCred-Event"]).toBe("batch.completed");
    expect(headers["Content-Length"]).toBe(String(Buffer.byteLength(body)));
  });

  it("does not mutate the caller's headers object", async () => {
    const headers = { "Content-Type": "application/json" };

    await fetchWithPinnedIp("https://example.com/", ["93.184.216.34"], {
      method: "POST",
      headers,
      body: "{}",
    });

    expect(headers).toEqual({ "Content-Type": "application/json" });
  });

  it("derives a multipart Content-Type (with boundary) for a FormData body", async () => {
    const form = new FormData();
    form.append("file", new Blob(["a,b\n1,2"], { type: "text/csv" }), "rows.csv");
    form.append("namespace", "ns");

    await fetchWithPinnedIp("https://dedi.example.com/dedi/bulk-upload", ["93.184.216.34"], {
      method: "POST",
      headers: { Accept: "application/json" },
      body: form,
    });

    const headers = captured[0].options["headers"] as Record<string, string>;
    expect(headers["Content-Type"]).toMatch(/^multipart\/form-data; boundary=/);
    expect(captured[0].body?.toString("utf8")).toContain("rows.csv");
    expect(headers["Content-Length"]).toBe(String(captured[0].body?.byteLength));
  });

  it("lets an explicit Content-Type win over the derived one (case-insensitive)", async () => {
    await fetchWithPinnedIp("https://example.com/", ["93.184.216.34"], {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });

    const headers = captured[0].options["headers"] as Record<string, string>;
    expect(headers["content-type"]).toBe("application/json");
    // No duplicate header in the other casing.
    expect(headers["Content-Type"]).toBeUndefined();
  });

  it("rejects when the request errors (e.g. TLS failure against a wrong pin)", async () => {
    nextResponse = {
      statusCode: 0,
      error: Object.assign(new Error("cert altname invalid"), {
        code: "ERR_TLS_CERT_ALTNAME_INVALID",
      }),
    };

    await expect(fetchWithPinnedIp("https://example.com/", ["1.1.1.1"])).rejects.toThrow(
      "cert altname invalid",
    );
  });
});
