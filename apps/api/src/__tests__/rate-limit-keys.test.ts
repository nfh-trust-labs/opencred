import { describe, it, expect } from "vitest";
import type { Context } from "hono";
import { namespaceRateLimitKey } from "../middleware/rate-limit-keys.js";

function fakeContext(opts: {
  jwtPayload?: { sub?: string };
  authorization?: string;
} = {}): Context {
  return {
    get: (key: string) => {
      if (key === "jwtPayload") return opts.jwtPayload;
      return undefined;
    },
    req: {
      header: (name: string) => {
        if (name.toLowerCase() === "authorization") return opts.authorization;
        return undefined;
      },
    },
  } as unknown as Context;
}

describe("namespaceRateLimitKey", () => {
  it("returns ns:<sub> when JWT subject is present", () => {
    const c = fakeContext({ jwtPayload: { sub: "org-123" } });
    expect(namespaceRateLimitKey(c)).toBe("ns:org-123");
  });

  it("returns tok:<first16chars> for Bearer token without JWT", () => {
    const token = "abcdefghijklmnopqrstuvwxyz1234567890";
    const c = fakeContext({ authorization: `Bearer ${token}` });
    expect(namespaceRateLimitKey(c)).toBe("tok:abcdefghijklmnop");
  });

  it("returns anon:credentials when no auth is provided", () => {
    const c = fakeContext();
    expect(namespaceRateLimitKey(c)).toBe("anon:credentials");
  });

  it("JWT subject takes priority over Bearer token", () => {
    const c = fakeContext({
      jwtPayload: { sub: "priority-ns" },
      authorization: "Bearer some-token-value-here",
    });
    expect(namespaceRateLimitKey(c)).toBe("ns:priority-ns");
  });

  it("falls back to anon:credentials for non-Bearer auth header", () => {
    const c = fakeContext({ authorization: "Basic dXNlcjpwYXNz" });
    expect(namespaceRateLimitKey(c)).toBe("anon:credentials");
  });

  it("falls back to anon:credentials when Bearer has empty token", () => {
    const c = fakeContext({ authorization: "Bearer " });
    expect(namespaceRateLimitKey(c)).toBe("anon:credentials");
  });
});
