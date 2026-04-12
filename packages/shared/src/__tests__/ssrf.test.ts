import { promises as dns } from "node:dns";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { isPrivateIP, resolveDnsForSsrf } from "../ssrf.js";

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
    ["224.0.0.1", true],
    ["239.255.255.255", true],
    ["240.0.0.1", true],
    ["255.255.255.255", true],
    ["100.64.0.1", true],
    ["100.127.255.254", true],
    ["198.18.0.1", true],
    ["198.19.255.255", true],
  ])("IPv4 %s → %s", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  it.each([
    ["8.8.8.8", false],
    ["1.1.1.1", false],
    ["172.32.0.1", false],
    ["192.169.1.1", false],
    ["100.63.255.255", false],
    ["198.17.0.1", false],
  ])("IPv4 public %s → %s", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  // IPv6 private ranges
  it.each([
    ["::1", true],
    ["::", true],
    ["fc00::1", true],
    ["fd12::1", true],
    ["fe80::1", true],
    ["ff02::1", true],
    ["0100::1", true],
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

vi.mock("node:dns", () => ({
  promises: {
    resolve4: vi.fn(),
    resolve6: vi.fn(),
  },
}));

function dnsError(code: string): Error {
  const err = new Error(`queryAAAA ${code}`);
  (err as NodeJS.ErrnoException).code = code;
  return err;
}

describe("resolveDnsForSsrf", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("returns addresses when both A and AAAA succeed with public IPs", async () => {
    vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
    vi.mocked(dns.resolve6).mockResolvedValue(["2606:2800:220:1:248:1893:25c8:1946"]);

    const result = await resolveDnsForSsrf("example.com");
    expect(result).toEqual(["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]);
  });

  it("returns A results when AAAA fails with ENODATA (no AAAA records)", async () => {
    vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
    vi.mocked(dns.resolve6).mockRejectedValue(dnsError("ENODATA"));

    const result = await resolveDnsForSsrf("example.com");
    expect(result).toEqual(["93.184.216.34"]);
  });

  it("returns A results when AAAA fails with ENOTFOUND", async () => {
    vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
    vi.mocked(dns.resolve6).mockRejectedValue(dnsError("ENOTFOUND"));

    const result = await resolveDnsForSsrf("example.com");
    expect(result).toEqual(["93.184.216.34"]);
  });

  it("returns AAAA results when A fails with ENODATA", async () => {
    vi.mocked(dns.resolve4).mockRejectedValue(dnsError("ENODATA"));
    vi.mocked(dns.resolve6).mockResolvedValue(["2606:2800:220:1:248:1893:25c8:1946"]);

    const result = await resolveDnsForSsrf("example.com");
    expect(result).toEqual(["2606:2800:220:1:248:1893:25c8:1946"]);
  });

  it("throws when both A and AAAA fail with benign errors (no records at all)", async () => {
    vi.mocked(dns.resolve4).mockRejectedValue(dnsError("ENOTFOUND"));
    vi.mocked(dns.resolve6).mockRejectedValue(dnsError("ENOTFOUND"));

    await expect(resolveDnsForSsrf("nonexistent.invalid")).rejects.toThrow(
      "DNS resolution returned no addresses",
    );
  });

  it("throws when AAAA times out (fail-closed on transient error)", async () => {
    vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
    vi.mocked(dns.resolve6).mockRejectedValue(dnsError("ETIMEOUT"));

    await expect(resolveDnsForSsrf("example.com")).rejects.toThrow(
      "DNS AAAA lookup failed",
    );
  });

  it("throws when A lookup has transient ESERVFAIL error", async () => {
    vi.mocked(dns.resolve4).mockRejectedValue(dnsError("ESERVFAIL"));
    vi.mocked(dns.resolve6).mockResolvedValue(["2606:2800:220:1:248:1893:25c8:1946"]);

    await expect(resolveDnsForSsrf("example.com")).rejects.toThrow(
      "DNS A lookup failed",
    );
  });

  it("throws when both lookups have transient errors", async () => {
    vi.mocked(dns.resolve4).mockRejectedValue(dnsError("ETIMEOUT"));
    vi.mocked(dns.resolve6).mockRejectedValue(dnsError("ECONNREFUSED"));

    await expect(resolveDnsForSsrf("example.com")).rejects.toThrow(
      "DNS A lookup failed",
    );
  });

  it("throws when A resolves to a private IP", async () => {
    vi.mocked(dns.resolve4).mockResolvedValue(["192.168.1.1"]);
    vi.mocked(dns.resolve6).mockRejectedValue(dnsError("ENODATA"));

    await expect(resolveDnsForSsrf("evil.example")).rejects.toThrow(
      "SSRF protection",
    );
  });

  it("throws when AAAA resolves to a private IPv6", async () => {
    vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
    vi.mocked(dns.resolve6).mockResolvedValue(["::1"]);

    await expect(resolveDnsForSsrf("evil.example")).rejects.toThrow(
      "SSRF protection",
    );
  });

  it("throws on DNS error without a code property (fail-closed)", async () => {
    vi.mocked(dns.resolve4).mockResolvedValue(["93.184.216.34"]);
    vi.mocked(dns.resolve6).mockRejectedValue(new Error("unexpected"));

    await expect(resolveDnsForSsrf("example.com")).rejects.toThrow(
      "DNS AAAA lookup failed",
    );
  });
});
