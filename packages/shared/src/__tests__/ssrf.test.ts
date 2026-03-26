import { describe, it, expect } from "vitest";
import { isPrivateIP } from "../ssrf.js";

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

  // IPv6 private ranges
  it.each([
    ["::1", true],
    ["fc00::1", true],
    ["fd12::1", true],
    ["fe80::1", true],
  ])("IPv6 %s → %s", (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  it.each([
    ["2001:4860:4860::8888", false],
  ])("IPv6 public %s → %s", (ip, expected) => {
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

  // Invalid input
  it("returns false for non-IP strings", () => {
    expect(isPrivateIP("not-an-ip")).toBe(false);
    expect(isPrivateIP("")).toBe(false);
  });
});
