import { describe, it, expect } from "vitest";
import { isPrivateIP } from "../ssrf.js";

describe("isPrivateIP", () => {
  // ─── IPv4 Private Ranges ────────────────────────────────────────

  it("identifies 10.x.x.x as private (RFC 1918)", () => {
    expect(isPrivateIP("10.0.0.1")).toBe(true);
    expect(isPrivateIP("10.255.255.255")).toBe(true);
    expect(isPrivateIP("10.100.50.25")).toBe(true);
  });

  it("identifies 172.16-31.x.x as private (RFC 1918)", () => {
    expect(isPrivateIP("172.16.0.1")).toBe(true);
    expect(isPrivateIP("172.31.255.255")).toBe(true);
    expect(isPrivateIP("172.20.0.1")).toBe(true);
  });

  it("does not flag 172.15 or 172.32 as private", () => {
    expect(isPrivateIP("172.15.0.1")).toBe(false);
    expect(isPrivateIP("172.32.0.1")).toBe(false);
  });

  it("identifies 192.168.x.x as private (RFC 1918)", () => {
    expect(isPrivateIP("192.168.0.1")).toBe(true);
    expect(isPrivateIP("192.168.255.255")).toBe(true);
  });

  it("identifies 127.x.x.x as loopback", () => {
    expect(isPrivateIP("127.0.0.1")).toBe(true);
    expect(isPrivateIP("127.255.255.255")).toBe(true);
  });

  it("identifies 169.254.x.x as link-local", () => {
    expect(isPrivateIP("169.254.0.1")).toBe(true);
    expect(isPrivateIP("169.254.169.254")).toBe(true);
  });

  it("identifies 0.x.x.x as reserved", () => {
    expect(isPrivateIP("0.0.0.0")).toBe(true);
  });

  // ─── IPv6 Private Ranges ────────────────────────────────────────

  it("identifies ::1 as IPv6 loopback", () => {
    expect(isPrivateIP("::1")).toBe(true);
  });

  it("identifies fc00::/fd00:: as unique-local", () => {
    expect(isPrivateIP("fc00::1")).toBe(true);
    expect(isPrivateIP("fd00::1")).toBe(true);
    expect(isPrivateIP("fdab::1")).toBe(true);
  });

  it("identifies fe80:: as link-local", () => {
    expect(isPrivateIP("fe80::1")).toBe(true);
    expect(isPrivateIP("fe80::abcd:1234")).toBe(true);
  });

  // ─── Public IPs ─────────────────────────────────────────────────

  it("does not flag public IPv4 addresses", () => {
    expect(isPrivateIP("8.8.8.8")).toBe(false);
    expect(isPrivateIP("1.1.1.1")).toBe(false);
    expect(isPrivateIP("93.184.216.34")).toBe(false);
    expect(isPrivateIP("203.0.113.1")).toBe(false);
  });

  it("does not flag public IPv6 addresses", () => {
    expect(isPrivateIP("2001:db8::1")).toBe(false);
    expect(isPrivateIP("2606:4700:4700::1111")).toBe(false);
  });

  // ─── Edge Cases ─────────────────────────────────────────────────

  it("returns false for non-IP strings", () => {
    expect(isPrivateIP("not-an-ip")).toBe(false);
    expect(isPrivateIP("")).toBe(false);
    expect(isPrivateIP("example.com")).toBe(false);
  });
});
