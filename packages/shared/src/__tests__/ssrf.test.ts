import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  isPrivateIP,
  resolveAndPinHostname,
  buildPinnedFetchTarget,
} from "../ssrf.js";

vi.mock("node:dns/promises", () => ({
  resolve4: vi.fn(),
  resolve6: vi.fn(),
}));

import { resolve4, resolve6 } from "node:dns/promises";

describe("isPrivateIP", () => {
  // IPv4 private ranges
  it.each([
    ["127.0.0.1", true],
    ["10.0.0.1", true],
    ["172.16.0.1", true],
    ["172.31.255.255", true],
    ["192.168.1.1", true],
    ["169.254.1.1", true],
    ["0.0.0.0", true],
  ])("IPv4 %s → %s", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  it.each([
    ["8.8.8.8", false],
    ["1.1.1.1", false],
    ["172.32.0.1", false],
    ["192.169.1.1", false],
  ])("IPv4 public %s → %s", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  // IPv4 CGNAT / benchmark / multicast / reserved ranges
  it.each([
    ["100.64.0.1", true], // CGNAT (RFC 6598)
    ["100.127.255.255", true], // CGNAT upper bound
    ["198.18.0.1", true], // benchmark testing (RFC 2544)
    ["198.19.255.255", true], // benchmark testing upper bound
    ["224.0.0.1", true], // multicast (RFC 5771)
    ["239.255.255.255", true], // multicast upper bound
    ["240.0.0.1", true], // reserved/future (RFC 1112)
    ["255.255.255.255", true], // reserved/future upper bound
  ])("IPv4 extended-private %s → %s", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  // IPs just outside the extended ranges — must remain public
  it.each([
    ["100.63.255.255", false], // just below CGNAT
    ["100.128.0.0", false], // just above CGNAT
    ["198.17.255.255", false], // just below benchmark range
    ["198.20.0.0", false], // just above benchmark range
    ["223.255.255.255", false], // just below multicast
  ])("IPv4 extended-public %s → %s", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  // IPv6 private ranges
  it.each([
    ["::1", true],
    ["fc00::1", true],
    ["fd12::1", true],
    ["fe80::1", true],
    ["ff00::1", true], // multicast
    ["ff02::1", true], // link-local multicast (all nodes)
  ])("IPv6 %s → %s", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  it.each([["2001:4860:4860::8888", false]])("IPv6 public %s → %s", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  // IPv4-mapped IPv6 — the critical SSRF vector
  it.each([
    ["::ffff:127.0.0.1", true],
    ["::ffff:10.0.0.1", true],
    ["::ffff:192.168.1.1", true],
    ["::ffff:172.16.0.1", true],
  ])("IPv4-mapped IPv6 %s → %s (private)", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  it.each([
    ["::ffff:8.8.8.8", false],
    ["::ffff:1.1.1.1", false],
  ])("IPv4-mapped IPv6 %s → %s (public)", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  // IPv4-mapped IPv6 hex form (::ffff:XXXX:XXXX)
  it.each([
    ["::ffff:7f00:0001", true], // 127.0.0.1
    ["::ffff:c0a8:0101", true], // 192.168.1.1
    ["::ffff:0a00:0001", true], // 10.0.0.1
    ["::ffff:ac10:0001", true], // 172.16.0.1
  ])("IPv4-mapped IPv6 hex %s → %s (private)", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  it.each([
    ["::ffff:0808:0808", false], // 8.8.8.8
    ["::ffff:0101:0101", false], // 1.1.1.1
  ])("IPv4-mapped IPv6 hex %s → %s (public)", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  // Invalid input
  it("returns false for non-IP strings", () => {
    expect(isPrivateIP("not-an-ip")).toBe(false);
    expect(isPrivateIP("")).toBe(false);
  });
});

describe("resolveAndPinHostname", () => {
  const resolve4Mock = vi.mocked(resolve4);
  const resolve6Mock = vi.mocked(resolve6);

  beforeEach(() => {
    resolve4Mock.mockReset();
    resolve6Mock.mockReset();
    // Default both to ENODATA so a forgotten setup fails clean.
    resolve4Mock.mockRejectedValue(new Error("ENODATA"));
    resolve6Mock.mockRejectedValue(new Error("ENODATA"));
  });

  afterEach(() => {
    resolve4Mock.mockReset();
    resolve6Mock.mockReset();
  });

  it("returns the first IPv4 address when public", async () => {
    resolve4Mock.mockResolvedValue(["93.184.216.34"]);

    const result = await resolveAndPinHostname("example.com");
    expect(result).toEqual({ address: "93.184.216.34", family: 4 });
  });

  it("falls back to IPv6 when no IPv4 records", async () => {
    resolve6Mock.mockResolvedValue(["2606:2800:220:1:248:1893:25c8:1946"]);

    const result = await resolveAndPinHostname("ipv6.example.com");
    expect(result).toEqual({
      address: "2606:2800:220:1:248:1893:25c8:1946",
      family: 6,
    });
  });

  it("rejects when ANY resolved IP is private (multi-A-record SSRF)", async () => {
    resolve4Mock.mockResolvedValue(["93.184.216.34", "127.0.0.1"]);

    await expect(resolveAndPinHostname("evil.example.com")).rejects.toThrow(
      /private\/reserved/,
    );
  });

  it("rejects when the only IPv4 record is private", async () => {
    resolve4Mock.mockResolvedValue(["10.0.0.1"]);

    await expect(resolveAndPinHostname("evil.example.com")).rejects.toThrow(
      /private\/reserved/,
    );
  });

  it("rejects when the only IPv6 record is private", async () => {
    resolve6Mock.mockResolvedValue(["::1"]);

    await expect(resolveAndPinHostname("evil.example.com")).rejects.toThrow(
      /private\/reserved/,
    );
  });

  it("rejects when both DNS lookups fail", async () => {
    await expect(resolveAndPinHostname("nonexistent.example.com")).rejects.toThrow(
      /DNS resolution failed/,
    );
  });

  it("DNS rebinding TOCTOU defence: only one resolution call per request", async () => {
    // The first call returns a public IP. A hypothetical re-resolution
    // would return loopback. The helper performs exactly one resolution
    // and returns the pinned address — callers must use that address
    // directly, not call back into resolveAndPinHostname.
    resolve4Mock
      .mockResolvedValueOnce(["93.184.216.34"])
      .mockResolvedValueOnce(["127.0.0.1"]);

    const result = await resolveAndPinHostname("rebinding.example.com");

    expect(resolve4Mock).toHaveBeenCalledTimes(1);
    expect(result.address).toBe("93.184.216.34");
  });

  it("honours an injected isPrivateIP predicate", async () => {
    resolve4Mock.mockResolvedValue(["8.8.8.8"]);

    // Reject everything as "private" using a custom predicate.
    await expect(
      resolveAndPinHostname("public.example.com", { isPrivateIP: () => true }),
    ).rejects.toThrow(/private\/reserved/);
  });
});

describe("buildPinnedFetchTarget", () => {
  it("rewrites the hostname to an IPv4 literal", () => {
    const result = buildPinnedFetchTarget("https://example.com/path?q=1", {
      address: "93.184.216.34",
      family: 4,
    });
    expect(result.url).toBe("https://93.184.216.34/path?q=1");
    expect(result.headers.Host).toBe("example.com");
  });

  it("rewrites the hostname to a bracketed IPv6 literal", () => {
    const result = buildPinnedFetchTarget("https://ipv6.example.com/", {
      address: "2606:2800:220:1:248:1893:25c8:1946",
      family: 6,
    });
    expect(result.url).toBe("https://[2606:2800:220:1:248:1893:25c8:1946]/");
    expect(result.headers.Host).toBe("ipv6.example.com");
  });

  it("preserves a non-default port in the Host header", () => {
    const result = buildPinnedFetchTarget("https://example.com:8443/foo", {
      address: "93.184.216.34",
      family: 4,
    });
    expect(result.url).toBe("https://93.184.216.34:8443/foo");
    expect(result.headers.Host).toBe("example.com:8443");
  });

  it("omits the default https port from the Host header", () => {
    const result = buildPinnedFetchTarget("https://example.com:443/foo", {
      address: "93.184.216.34",
      family: 4,
    });
    expect(result.headers.Host).toBe("example.com");
  });

  it("preserves the path and query string", () => {
    const result = buildPinnedFetchTarget(
      "https://example.com/.well-known/did.json?v=1",
      { address: "93.184.216.34", family: 4 },
    );
    expect(result.url).toBe("https://93.184.216.34/.well-known/did.json?v=1");
  });
});
