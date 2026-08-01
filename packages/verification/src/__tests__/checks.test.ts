import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  checkDates,
  checkRevocation,
  checkBitstringStatusList,
  checkKeyStatus,
  checkRegistryAnchor,
  resolveAndValidateIp,
  _validateStatusListUrl,
  MAX_COMPRESSED_SIZE,
} from "../checks.js";
import type { DeDiClient } from "@opencred/dedi-client";
import { DeDiClientError } from "@opencred/dedi-client";
import type { DIDResolver } from "@opencred/did";
import { fetchWithPinnedIp } from "@opencred/shared";
import { gzipSync } from "node:zlib";

vi.mock("node:dns/promises", () => ({
  resolve4: vi.fn(),
  resolve6: vi.fn(),
}));

// The status-list fetch must go through `fetchWithPinnedIp` (connection
// pinned to the DNS-validated IP) — a plain `fetch(url)` would re-resolve
// the hostname and reopen the DNS-rebinding TOCTOU window. Everything else
// in @opencred/shared stays real.
vi.mock("@opencred/shared", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return { ...actual, fetchWithPinnedIp: vi.fn() };
});

import { resolve4, resolve6 } from "node:dns/promises";

const mockResolve4 = vi.mocked(resolve4);
const mockResolve6 = vi.mocked(resolve6);
const mockPinnedFetch = vi.mocked(fetchWithPinnedIp);

beforeEach(() => {
  vi.restoreAllMocks();
  // Default: resolve to a public IP so existing tests pass
  mockResolve4.mockResolvedValue(["93.184.216.34"]);
  mockResolve6.mockResolvedValue(["2606:2800:220:1:248:1893:25c8:1946"]);
});

describe("checkDates", () => {
  it("should pass for a credential within its validity period", () => {
    const now = new Date("2026-06-15T12:00:00Z");
    const result = checkDates("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", now);
    expect(result.passed).toBe(true);
    expect(result.name).toBe("date");
  });

  it("should pass when only validFrom is set and current time is after", () => {
    const now = new Date("2026-06-15T12:00:00Z");
    const result = checkDates("2026-01-01T00:00:00Z", undefined, now);
    expect(result.passed).toBe(true);
  });

  it("should pass when no dates are provided", () => {
    const result = checkDates(undefined, undefined);
    expect(result.passed).toBe(true);
  });

  it("should fail when credential is not yet valid (validFrom in future)", () => {
    const now = new Date("2025-06-15T12:00:00Z");
    const result = checkDates("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", now);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("not yet valid");
  });

  it("should fail when credential is expired (validUntil in past)", () => {
    const now = new Date("2028-01-01T12:00:00Z");
    const result = checkDates("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", now);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("expired");
  });

  it("should fail for invalid validFrom date", () => {
    const result = checkDates("not-a-date", undefined);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Invalid validFrom");
  });

  it("should fail for invalid validUntil date", () => {
    const result = checkDates("2026-01-01T00:00:00Z", "not-a-date");
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Invalid validUntil");
  });
});

describe("checkRevocation", () => {
  it("should pass when credential is not revoked", async () => {
    const mockClient = {
      queryRevocationHash: vi.fn().mockResolvedValue({ revoked: false }),
    } as unknown as DeDiClient;

    const result = await checkRevocation({ id: "test" }, mockClient);
    expect(result.passed).toBe(true);
    expect(result.name).toBe("revocation");
  });

  it("should fail when credential is revoked", async () => {
    const mockClient = {
      queryRevocationHash: vi.fn().mockResolvedValue({
        revoked: true,
        revokedAt: "2026-06-01T00:00:00Z",
      }),
    } as unknown as DeDiClient;

    const result = await checkRevocation({ id: "test" }, mockClient);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("revoked");
    expect(result.detail).toContain("2026-06-01T00:00:00Z");
  });

  it("includes the revocation reason in the detail when present (#658)", async () => {
    const mockClient = {
      queryRevocationHash: vi.fn().mockResolvedValue({
        revoked: true,
        revokedAt: "2026-06-01T00:00:00Z",
        reason: "Key compromised",
      }),
    } as unknown as DeDiClient;

    const result = await checkRevocation({ id: "test" }, mockClient);
    expect(result.passed).toBe(false);
    expect(result.detail).toBe(
      "Credential revoked at 2026-06-01T00:00:00Z. Reason: Key compromised.",
    );
  });

  it("omits the reason clause when no reason is supplied (detail unchanged)", async () => {
    const mockClient = {
      queryRevocationHash: vi.fn().mockResolvedValue({
        revoked: true,
        revokedAt: "2026-06-01T00:00:00Z",
      }),
    } as unknown as DeDiClient;

    const result = await checkRevocation({ id: "test" }, mockClient);
    expect(result.detail).toBe("Credential revoked at 2026-06-01T00:00:00Z");
    expect(result.detail).not.toContain("Reason");
  });

  it("should fail when DeDi is unavailable", async () => {
    const mockClient = {
      queryRevocationHash: vi.fn().mockRejectedValue(new Error("Connection refused")),
    } as unknown as DeDiClient;

    const result = await checkRevocation({ id: "test" }, mockClient);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("unavailable");
  });
});

// --- SSRF prevention tests ---
//
// The base `isPrivateIP` unit tests live in `@opencred/shared` (the canonical
// implementation). Here we regression-test that every IPv4/IPv6 range the
// previous local implementation rejected is still rejected when surfaced
// through `validateStatusListUrl`, which is how the verification package
// consumes the helper.

describe("validateStatusListUrl — private/reserved IP ranges", () => {
  const privateIPv4s: Array<[string, string]> = [
    ["10.0.0.0/8", "10.0.0.1"],
    ["10.0.0.0/8 upper", "10.255.255.255"],
    ["172.16.0.0/12", "172.16.0.1"],
    ["172.16.0.0/12 upper", "172.31.255.255"],
    ["192.168.0.0/16", "192.168.0.1"],
    ["192.168.0.0/16 upper", "192.168.255.255"],
    ["127.0.0.0/8 loopback", "127.0.0.1"],
    ["127.0.0.0/8 loopback upper", "127.255.255.255"],
    ["0.0.0.0/8", "0.0.0.0"],
    ["169.254.0.0/16 link-local", "169.254.0.1"],
    ["100.64.0.0/10 CGNAT", "100.64.0.1"],
    ["100.64.0.0/10 CGNAT upper", "100.127.255.255"],
    ["198.18.0.0/15 benchmarking", "198.18.0.1"],
    ["198.18.0.0/15 upper", "198.19.255.255"],
    ["224.0.0.0/4 multicast", "224.0.0.1"],
    ["224.0.0.0/4 multicast upper", "239.255.255.255"],
    ["240.0.0.0/4 reserved", "240.0.0.1"],
    ["255.255.255.255 broadcast", "255.255.255.255"],
  ];

  it.each(privateIPv4s)("rejects IPv4 %s (%s)", (_label, ip) => {
    const result = _validateStatusListUrl(`https://${ip}/status/1`);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.detail).toContain("private/reserved IP");
    }
  });

  const privateIPv6s: Array<[string, string]> = [
    ["::1 loopback", "[::1]"],
    [":: unspecified", "[::]"],
    ["fc00::/7 ULA", "[fc00::1]"],
    ["fd00::/8 ULA", "[fd00::1]"],
    ["fe80::/10 link-local", "[fe80::1]"],
    ["ff00::/8 multicast", "[ff02::1]"],
    ["0100::/64 discard", "[0100::1]"],
    ["::ffff:IPv4-mapped dotted", "[::ffff:127.0.0.1]"],
    ["::ffff:IPv4-mapped dotted private", "[::ffff:10.0.0.1]"],
  ];

  it.each(privateIPv6s)("rejects IPv6 %s (%s)", (_label, bracketed) => {
    const result = _validateStatusListUrl(`https://${bracketed}/status/1`);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      // `[::1]` is caught by the static PRIVATE_HOSTNAMES set before the IP
      // check runs; every other IPv6 literal takes the isPrivateIP branch.
      expect(result.detail).toMatch(/private\/(?:reserved IP|loopback host)/);
    }
  });

  it("accepts public IPv4 addresses", () => {
    expect(_validateStatusListUrl("https://8.8.8.8/status/1").valid).toBe(true);
    expect(_validateStatusListUrl("https://1.1.1.1/status/1").valid).toBe(true);
    expect(_validateStatusListUrl("https://203.0.113.1/status/1").valid).toBe(true);
  });
});

describe("validateStatusListUrl", () => {
  it("should accept valid HTTPS URLs", () => {
    const result = _validateStatusListUrl("https://example.com/status/1");
    expect(result.valid).toBe(true);
  });

  it("should reject HTTP URLs", () => {
    const result = _validateStatusListUrl("http://example.com/status/1");
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.detail).toContain("HTTPS");
  });

  it("should reject non-URL strings", () => {
    const result = _validateStatusListUrl("not-a-url");
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.detail).toContain("Invalid");
  });

  it("should reject localhost", () => {
    const result = _validateStatusListUrl("https://localhost/status/1");
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.detail).toContain("private");
  });

  it("should reject private IP addresses in URL", () => {
    expect(_validateStatusListUrl("https://127.0.0.1/status/1").valid).toBe(false);
    expect(_validateStatusListUrl("https://10.0.0.1/status/1").valid).toBe(false);
    expect(_validateStatusListUrl("https://192.168.1.1/status/1").valid).toBe(false);
    expect(_validateStatusListUrl("https://[::1]/status/1").valid).toBe(false);
  });

  it("should enforce domain allowlist when provided", () => {
    const result = _validateStatusListUrl("https://example.com/status/1", ["trusted.org"]);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.detail).toContain("allowlist");
  });

  it("should accept URLs on the domain allowlist", () => {
    const result = _validateStatusListUrl("https://status.trusted.org/list/1", ["trusted.org"]);
    expect(result.valid).toBe(true);
  });

  it("should accept exact domain match on allowlist", () => {
    const result = _validateStatusListUrl("https://trusted.org/list/1", ["trusted.org"]);
    expect(result.valid).toBe(true);
  });
});

// --- DNS rebinding prevention tests ---

describe("resolveAndValidateIp", () => {
  it("should reject when DNS resolves to a private IPv4 address", async () => {
    mockResolve4.mockResolvedValue(["127.0.0.1"]);

    await expect(resolveAndValidateIp("evil.example.com")).rejects.toThrow(
      "DNS resolved to private/reserved IP",
    );
  });

  it("should reject when any resolved IP is private (mixed results)", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34", "10.0.0.1"]);

    await expect(resolveAndValidateIp("evil.example.com")).rejects.toThrow(
      "DNS resolved to private/reserved IP",
    );
  });

  it("should resolve to public IPv4 successfully", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34"]);

    const result = await resolveAndValidateIp("example.com");
    expect(result).toEqual({ address: "93.184.216.34", family: 4 });
  });

  it("should fall back to IPv6 when resolve4 fails", async () => {
    mockResolve4.mockRejectedValue(new Error("ENODATA"));
    mockResolve6.mockResolvedValue(["2606:2800:220:1:248:1893:25c8:1946"]);

    const result = await resolveAndValidateIp("ipv6only.example.com");
    expect(result).toEqual({ address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 });
  });

  it("should fall back to IPv6 when resolve4 returns empty", async () => {
    mockResolve4.mockResolvedValue([]);
    mockResolve6.mockResolvedValue(["2606:2800:220:1:248:1893:25c8:1946"]);

    const result = await resolveAndValidateIp("ipv6only.example.com");
    expect(result).toEqual({ address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 });
  });

  it("should throw when both resolve4 and resolve6 fail", async () => {
    mockResolve4.mockRejectedValue(new Error("ENOTFOUND"));
    mockResolve6.mockRejectedValue(new Error("ENOTFOUND"));

    await expect(resolveAndValidateIp("nonexistent.example.com")).rejects.toThrow(
      "DNS resolution failed",
    );
  });

  it("should reject private IPv6 addresses (loopback)", async () => {
    mockResolve4.mockRejectedValue(new Error("ENODATA"));
    mockResolve6.mockResolvedValue(["::1"]);

    await expect(resolveAndValidateIp("evil.example.com")).rejects.toThrow(
      "DNS resolved to private/reserved IP",
    );
  });
});

// --- BitstringStatusList fetch-timeout regression (P1-02 / #469) ---
//
// The bitstring-status fetch previously had no AbortSignal, so a stalled
// remote host could hold the verify request open indefinitely. The fix
// adds a 10 s AbortController. This test asserts the abort is wired by
// stubbing fetch with a promise that rejects when the AbortSignal fires.

describe("checkBitstringStatusList — fetch timeout (P1-02)", () => {
  it("aborts the fetch after ~10s when the remote host stalls", async () => {
    // Stub the pinned fetch so it observes the AbortSignal and rejects with
    // AbortError as soon as the signal fires. We don't use real timers here —
    // we just prove the signal is passed through.
    mockPinnedFetch.mockImplementation(
      (_url: string | URL, _addresses: readonly string[], opts?: { signal?: AbortSignal }) => {
        return new Promise((_resolve, reject) => {
          opts?.signal?.addEventListener("abort", () => {
            reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
          });
        });
      },
    );
    vi.useFakeTimers();

    const resultPromise = checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://example.com/status/1",
    });

    // Fast-forward past the 10 s abort.
    await vi.advanceTimersByTimeAsync(11_000);
    const result = await resultPromise;

    expect(result.passed).toBe(false);
    expect(mockPinnedFetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(Array),
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );

    vi.useRealTimers();
  });
});

// --- BitstringStatusList tests ---

describe("checkBitstringStatusList", () => {
  function createStatusListResponse(bits: number[], listSize: number = 16): string {
    const byteCount = Math.ceil(listSize / 8);
    const buffer = Buffer.alloc(byteCount, 0);
    for (const bitIndex of bits) {
      const byteIdx = Math.floor(bitIndex / 8);
      const bitIdx = bitIndex % 8;
      buffer[byteIdx] |= 0x80 >> bitIdx;
    }
    const compressed = gzipSync(buffer);
    return compressed.toString("base64");
  }

  it("should pass when credential is not revoked in status list", async () => {
    const encodedList = createStatusListResponse([3, 7], 16);
    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue({
        credentialSubject: {
          type: "BitstringStatusList",
          statusPurpose: "revocation",
          encodedList,
        },
      }),
    };
    mockPinnedFetch.mockResolvedValue(mockResponse as unknown as Response);

    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://example.com/status/1",
    });

    expect(result.passed).toBe(true);
    expect(result.name).toBe("bitstringStatus");

    vi.unstubAllGlobals();
  });

  it("should fail when credential is revoked in status list", async () => {
    const encodedList = createStatusListResponse([3, 7], 16);
    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue({
        credentialSubject: {
          type: "BitstringStatusList",
          statusPurpose: "revocation",
          encodedList,
        },
      }),
    };
    mockPinnedFetch.mockResolvedValue(mockResponse as unknown as Response);

    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "3",
      statusListCredential: "https://example.com/status/1",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("revoked");

    vi.unstubAllGlobals();
  });

  it("should fail when status list fetch fails", async () => {
    const mockResponse = { ok: false, status: 500 };
    mockPinnedFetch.mockResolvedValue(mockResponse as unknown as Response);

    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://example.com/status/1",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Failed to fetch");

    vi.unstubAllGlobals();
  });

  it("should fail when statusListIndex is missing", async () => {
    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListCredential: "https://example.com/status/1",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Missing statusListIndex");
  });

  it("should fail when statusListIndex is out of range", async () => {
    const encodedList = createStatusListResponse([], 16);
    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue({
        credentialSubject: {
          type: "BitstringStatusList",
          statusPurpose: "revocation",
          encodedList,
        },
      }),
    };
    mockPinnedFetch.mockResolvedValue(mockResponse as unknown as Response);

    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "9999",
      statusListCredential: "https://example.com/status/1",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("out of range");

    vi.unstubAllGlobals();
  });

  // --- #123: SSRF prevention tests ---

  it("should reject HTTP URLs (non-HTTPS)", async () => {
    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "http://example.com/status/1",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("HTTPS");
  });

  it("should reject URLs pointing to private IPs", async () => {
    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://127.0.0.1/status/1",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("private");
  });

  it("should reject URLs pointing to localhost", async () => {
    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://localhost/status/1",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("private");
  });

  it("should reject URLs pointing to internal IPs", async () => {
    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://10.0.0.1/status/1",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("private");
  });

  // Regression: consolidating on the canonical isPrivateIP must not lose
  // coverage of any range the previous local implementation rejected.
  // Each entry below is a hostname that DNS-resolves to a private/reserved
  // address; checkBitstringStatusList must still reject it via the DNS
  // rebinding protection path.
  describe("rejects DNS-resolved private ranges (MED-01 regression)", () => {
    const privateRanges: Array<[label: string, ip: string]> = [
      ["10.0.0.0/8", "10.0.0.1"],
      ["172.16.0.0/12", "172.16.0.1"],
      ["172.16.0.0/12 upper", "172.31.255.255"],
      ["192.168.0.0/16", "192.168.1.1"],
      ["127.0.0.0/8 loopback", "127.0.0.1"],
      ["0.0.0.0/8", "0.0.0.0"],
      ["169.254.0.0/16 link-local", "169.254.1.1"],
      ["100.64.0.0/10 CGNAT", "100.64.0.1"],
      ["100.64.0.0/10 CGNAT upper", "100.127.255.255"],
      ["198.18.0.0/15 benchmarking", "198.18.0.1"],
      ["198.18.0.0/15 upper", "198.19.255.255"],
      ["224.0.0.0/4 multicast", "224.0.0.1"],
      ["240.0.0.0/4 reserved", "240.0.0.1"],
      ["255.255.255.255 broadcast", "255.255.255.255"],
    ];

    it.each(privateRanges)("rejects hostname resolving to IPv4 %s (%s)", async (_label, ip) => {
      mockResolve4.mockResolvedValue([ip]);
      mockResolve6.mockRejectedValue(Object.assign(new Error("ENODATA"), { code: "ENODATA" }));

      const result = await checkBitstringStatusList({
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "0",
        statusListCredential: "https://status.example.org/status/1",
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("private/reserved IP");
    });

    const privateIPv6s: Array<[label: string, ip: string]> = [
      ["::1 loopback", "::1"],
      [":: unspecified", "::"],
      ["fc00::/7 ULA", "fc00::1"],
      ["fd00::/8 ULA", "fd00::1"],
      ["fe80::/10 link-local", "fe80::1"],
      ["ff00::/8 multicast", "ff02::1"],
    ];

    it.each(privateIPv6s)("rejects hostname resolving to IPv6 %s (%s)", async (_label, ip) => {
      mockResolve4.mockRejectedValue(Object.assign(new Error("ENODATA"), { code: "ENODATA" }));
      mockResolve6.mockResolvedValue([ip]);

      const result = await checkBitstringStatusList({
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "0",
        statusListCredential: "https://status.example.org/status/1",
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("private/reserved IP");
    });
  });

  it("should reject invalid URL strings", async () => {
    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "not-a-url",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Invalid");
  });

  it("should enforce domain allowlist when provided", async () => {
    const result = await checkBitstringStatusList(
      {
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "0",
        statusListCredential: "https://untrusted.com/status/1",
      },
      { allowedDomains: ["trusted.org"] },
    );

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("allowlist");
  });

  it("does not follow redirects — a 3xx surfaces as a failed check", async () => {
    // fetchWithPinnedIp never follows redirects (https.request has no
    // redirect-following); a redirect must not be chased to a host that was
    // never SSRF-validated. A 3xx therefore surfaces as a non-ok response.
    mockPinnedFetch.mockResolvedValue({ ok: false, status: 301 } as unknown as Response);

    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://example.com/status/1",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("HTTP 301");
  });

  // --- #127: Size limit tests ---

  it("should reject compressed data exceeding MAX_COMPRESSED_SIZE", async () => {
    // Create a large base64 string that decodes to > 1MB
    const largeBuffer = Buffer.alloc(MAX_COMPRESSED_SIZE + 1, 0x41);
    const largeBase64 = largeBuffer.toString("base64");

    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue({
        credentialSubject: {
          type: "BitstringStatusList",
          statusPurpose: "revocation",
          encodedList: largeBase64,
        },
      }),
    };
    mockPinnedFetch.mockResolvedValue(mockResponse as unknown as Response);

    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://example.com/status/1",
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("maximum size");

    vi.unstubAllGlobals();
  });

  // --- DNS rebinding prevention tests ---

  describe("DNS rebinding prevention", () => {
    it("should fail when DNS resolves to a private IP (rebinding attack)", async () => {
      mockResolve4.mockResolvedValue(["127.0.0.1"]);

      const result = await checkBitstringStatusList({
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "0",
        statusListCredential: "https://evil.example.com/status/1",
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("DNS resolved to private/reserved IP");
      expect(mockPinnedFetch).not.toHaveBeenCalled();
    });

    it("pins the validated IP for the connection while the URL keeps the hostname", async () => {
      mockResolve4.mockResolvedValue(["93.184.216.34"]);
      const encodedList = createStatusListResponse([], 16);
      const mockResponse = {
        ok: true,
        json: vi.fn().mockResolvedValue({
          credentialSubject: {
            type: "BitstringStatusList",
            statusPurpose: "revocation",
            encodedList,
          },
        }),
      };
      mockPinnedFetch.mockResolvedValue(mockResponse as unknown as Response);

      const result = await checkBitstringStatusList({
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "0",
        statusListCredential: "https://example.com/status/1",
      });

      expect(result.passed).toBe(true);
      // The URL keeps the original hostname (TLS certificate validation runs
      // against it) and the connection is pinned to the DNS-validated IP.
      // (Putting the IP in the URL with a Host header — the previous
      // approach — fails TLS validation with ERR_TLS_CERT_ALTNAME_INVALID.)
      const [calledUrl, pinnedAddresses] = mockPinnedFetch.mock.calls[0];
      expect(String(calledUrl)).toBe("https://example.com/status/1");
      expect(pinnedAddresses).toEqual(["93.184.216.34"]);
    });

    it("connects directly to a validated literal-IP URL without DNS", async () => {
      const encodedList = createStatusListResponse([], 16);
      const mockResponse = {
        ok: true,
        json: vi.fn().mockResolvedValue({
          credentialSubject: {
            type: "BitstringStatusList",
            statusPurpose: "revocation",
            encodedList,
          },
        }),
      };
      mockPinnedFetch.mockResolvedValue(mockResponse as unknown as Response);

      const result = await checkBitstringStatusList({
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "0",
        statusListCredential: "https://93.184.216.34/status/1",
      });

      expect(result.passed).toBe(true);
      // Literal IP: no DNS involved, so nothing can rebind — the literal is
      // its own pin.
      expect(mockResolve4).not.toHaveBeenCalled();
      expect(mockPinnedFetch.mock.calls[0][1]).toEqual(["93.184.216.34"]);
    });

    it("should fail when DNS resolution fails entirely", async () => {
      mockResolve4.mockRejectedValue(new Error("ENOTFOUND"));
      mockResolve6.mockRejectedValue(new Error("ENOTFOUND"));

      const result = await checkBitstringStatusList({
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "0",
        statusListCredential: "https://nonexistent.example.com/status/1",
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("DNS resolution failed");
      expect(mockPinnedFetch).not.toHaveBeenCalled();
    });
  });

  // --- #128: Proof verification tests ---

  it("should fail when status list credential proof is invalid and didResolver is provided", async () => {
    const encodedList = createStatusListResponse([], 16);
    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue({
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "ecdsa-rdfc-2019",
          verificationMethod: "did:key:z6MkInvalidKey#z6MkInvalidKey",
          proofPurpose: "assertionMethod",
          proofValue: "zInvalidProof",
        },
        credentialSubject: {
          type: "BitstringStatusList",
          statusPurpose: "revocation",
          encodedList,
        },
      }),
    };
    mockPinnedFetch.mockResolvedValue(mockResponse as unknown as Response);

    const mockResolver = {
      resolve: vi.fn().mockResolvedValue({
        didDocument: { verificationMethod: [] },
      }),
    };

    const result = await checkBitstringStatusList(
      {
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "0",
        statusListCredential: "https://example.com/status/1",
      },
      { didResolver: mockResolver as unknown as DIDResolver },
    );

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Status list credential proof invalid");

    vi.unstubAllGlobals();
  });

  it("should skip proof verification when no didResolver is provided", async () => {
    const encodedList = createStatusListResponse([], 16);
    const mockResponse = {
      ok: true,
      json: vi.fn().mockResolvedValue({
        credentialSubject: {
          type: "BitstringStatusList",
          statusPurpose: "revocation",
          encodedList,
        },
      }),
    };
    mockPinnedFetch.mockResolvedValue(mockResponse as unknown as Response);

    const result = await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://example.com/status/1",
    });

    // Should pass since proof verification is skipped without a resolver
    expect(result.passed).toBe(true);

    vi.unstubAllGlobals();
  });
});

describe("checkKeyStatus", () => {
  // A did:key issuer with no proof: `extractVerificationMethod` derives the
  // conventional `${did}#${methodSpecificId}` verification method, and the
  // namespace travels in `credentialStatus.id` (a DeDi lookup URL). Both are
  // needed for the resolveKey path to fire.
  const didKeyVm = "did:key:z6Mkfoo#z6Mkfoo";
  function makeDidKeyCredential(issuer = "did:key:z6Mkfoo"): Record<string, unknown> {
    return {
      issuer,
      credentialStatus: {
        id: "https://dedi.example.com/dedi/lookup/example.com/vc-revocation-registry/abc123",
        type: "RevocationList2020Status",
      },
    };
  }

  // A did:web issuer carrying an embedded proof: the verification method comes
  // straight off the proof, and the namespace is the DID's host portion.
  function makeDidWebCredential(
    did = "did:web:acme.com",
    vm = `${did}#key-0`,
  ): Record<string, unknown> {
    return {
      issuer: did,
      proof: { type: "DataIntegrityProof", verificationMethod: vm },
    };
  }

  it("passes silently when no DeDi client is configured", async () => {
    const result = await checkKeyStatus(makeDidKeyCredential());
    expect(result.passed).toBe(true);
    expect(result.name).toBe("keyStatus");
  });

  it("passes 'not checked' when no verification method can be determined", async () => {
    // A did:web issuer with no embedded proof: there's no proof VM and the
    // did:key fallback doesn't apply, so the VM is undefined.
    const mockClient = { resolveKey: vi.fn() } as unknown as DeDiClient;
    const result = await checkKeyStatus({ issuer: "did:web:acme.com" }, mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toMatch(/no verification method/i);
    expect(mockClient.resolveKey).not.toHaveBeenCalled();
  });

  it("did:key with status 'active' → pass (no detail)", async () => {
    const mockClient = {
      resolveKey: vi.fn().mockResolvedValue({
        keyId: didKeyVm,
        controllerDid: "did:key:z6Mkfoo",
        algorithm: "Ed25519",
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
        purpose: ["assertionMethod"],
        status: "active",
      }),
    } as unknown as DeDiClient;
    const result = await checkKeyStatus(makeDidKeyCredential(), mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toBeUndefined();
    // VM derived from did:key issuer, namespace from credentialStatus.id.
    expect(mockClient.resolveKey).toHaveBeenCalledWith(didKeyVm, "example.com");
  });

  it("did:key with status 'rotated' → passes with a 'cleanly rotated' detail", async () => {
    // A clean rotation leaves credentials signed by the old key valid — so
    // the check still PASSES, it just annotates that the key was rotated.
    const mockClient = {
      resolveKey: vi.fn().mockResolvedValue({
        keyId: didKeyVm,
        controllerDid: "did:key:z6Mkfoo",
        algorithm: "Ed25519",
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
        purpose: ["assertionMethod"],
        status: "rotated",
      }),
    } as unknown as DeDiClient;
    const result = await checkKeyStatus(makeDidKeyCredential(), mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toMatch(/rotated/i);
    expect(result.detail).toMatch(/remains valid/i);
  });

  it("status 'revoked' → fails (maps to top-level REVOKED in the verifier)", async () => {
    const mockClient = {
      resolveKey: vi.fn().mockResolvedValue({
        keyId: `${"did:web:acme.com"}#key-0`,
        controllerDid: "did:web:acme.com",
        algorithm: "ES256",
        publicKeyJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
        purpose: ["assertionMethod"],
        status: "revoked",
      }),
    } as unknown as DeDiClient;
    const result = await checkKeyStatus(makeDidWebCredential(), mockClient);
    expect(result.passed).toBe(false);
    expect(result.detail).toMatch(/revoked/i);
    expect(result.detail).toMatch(/compromised/i);
  });

  it("derives the namespace from a did:web issuer host and the VM from the proof", async () => {
    // `did:web:acme.com:eu:issuers` → namespace `acme.com`; the proof's
    // verificationMethod names the exact signing key.
    const did = "did:web:acme.com:eu:issuers";
    const vm = `${did}#key-3`;
    const mockClient = {
      resolveKey: vi.fn().mockResolvedValue({
        keyId: vm,
        controllerDid: did,
        algorithm: "ES256",
        publicKeyJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
        purpose: ["assertionMethod"],
        status: "active",
      }),
    } as unknown as DeDiClient;
    const result = await checkKeyStatus(makeDidWebCredential(did, vm), mockClient);
    expect(result.passed).toBe(true);
    expect(mockClient.resolveKey).toHaveBeenCalledWith(vm, "acme.com");
  });

  it("DeDi 404 (no record for this key) → passes with 'no registry record' detail", async () => {
    const mockClient = {
      resolveKey: vi.fn().mockRejectedValue(new DeDiClientError("DeDi API error: 404", 404)),
    } as unknown as DeDiClient;
    const result = await checkKeyStatus(makeDidKeyCredential(), mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toMatch(/no registry record/i);
  });

  it("DeDi 400 (namespace undeterminable) → passes with 'namespace could not be determined'", async () => {
    const mockClient = {
      resolveKey: vi
        .fn()
        .mockRejectedValue(
          new DeDiClientError("No namespace provided and no defaultNamespace configured", 400),
        ),
    } as unknown as DeDiClient;
    const result = await checkKeyStatus(makeDidKeyCredential(), mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toMatch(/namespace could not be determined/i);
  });

  it("DeDi outage (non-404/400) → passes with 'Key status unknown' detail", async () => {
    const mockClient = {
      resolveKey: vi.fn().mockRejectedValue(new DeDiClientError("network timeout", 502)),
    } as unknown as DeDiClient;
    const result = await checkKeyStatus(makeDidKeyCredential(), mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toMatch(/key status unknown/i);
  });

  it("passes 'not checked' for non-did:key/web issuers with no proof VM", async () => {
    // Other DID methods (ion, sov, etc.) with no embedded proof produce no
    // verification method, so the check short-circuits to a non-failing pass
    // and never calls resolveKey.
    const mockClient = { resolveKey: vi.fn() } as unknown as DeDiClient;
    const result = await checkKeyStatus({ issuer: "did:ion:abc" }, mockClient);
    expect(result.passed).toBe(true);
    expect(mockClient.resolveKey).not.toHaveBeenCalled();
  });
});

describe("checkRegistryAnchor", () => {
  // A did:key issuer with no proof: `extractVerificationMethod` derives the
  // conventional `${did}#${methodSpecificId}` verification method that the
  // anchor check resolves against the key registry.
  const didKeyVm = "did:key:z6Mkfoo#z6Mkfoo";
  function makeCredential(issuer: string): Record<string, unknown> {
    return { issuer };
  }

  it("passes silently when no DeDi client is configured", async () => {
    const result = await checkRegistryAnchor(makeCredential("did:key:z6Mkfoo"));
    expect(result.passed).toBe(true);
    expect(result.name).toBe("registryAnchor");
    expect(result.detail).toBeUndefined();
  });

  it("passes silently when no verification method can be determined", async () => {
    // A did:web issuer with no embedded proof yields no VM, so the advisory
    // check short-circuits to a silent pass and never calls resolveKey.
    const mockClient = { resolveKey: vi.fn() } as unknown as DeDiClient;
    const result = await checkRegistryAnchor({ issuer: "did:web:acme.com" }, mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toBeUndefined();
    expect(mockClient.resolveKey).not.toHaveBeenCalled();
  });

  it("passes silently for non-did:key issuers with no proof VM", async () => {
    const mockClient = { resolveKey: vi.fn() } as unknown as DeDiClient;
    const result = await checkRegistryAnchor(makeCredential("did:ion:abc"), mockClient);
    expect(result.passed).toBe(true);
    expect(mockClient.resolveKey).not.toHaveBeenCalled();
  });

  it("passes with anchor metadata when proof is present and creator matches", async () => {
    const mockClient = {
      resolveKey: vi.fn().mockResolvedValue({
        keyId: didKeyVm,
        controllerDid: "did:key:z6Mkfoo",
        algorithm: "Ed25519",
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
        purpose: ["assertionMethod"],
        status: "active",
        proof: {
          type: "DediRecordProof2026",
          namespace_did: "did:cord:ns:example",
          creator_did: "did:key:z6Mkfoo",
          digest: "abc123def456789012",
          network_genesis: "0xCORDgenesishash1234",
        },
      }),
    } as unknown as DeDiClient;
    const result = await checkRegistryAnchor(makeCredential("did:key:z6Mkfoo"), mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toMatch(/anchored on CORD/i);
    expect(result.detail).toContain("did:key:z6Mkfoo");
    // Long values should be abbreviated for display.
    expect(result.detail).toContain("abc123def456");
    expect(result.detail).toContain("0xCORDgenesi");
  });

  it("passes with anchor metadata even when network_genesis is null", async () => {
    // A record can be in DeDi without being anchored to a specific network
    // yet (`network_genesis: null`). Render the rest of the proof without
    // a network suffix in that case.
    const mockClient = {
      resolveKey: vi.fn().mockResolvedValue({
        keyId: didKeyVm,
        controllerDid: "did:key:z6Mkfoo",
        algorithm: "Ed25519",
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
        purpose: ["assertionMethod"],
        status: "active",
        proof: {
          type: "DediRecordProof2026",
          namespace_did: "did:cord:ns:example",
          creator_did: "did:key:z6Mkfoo",
          digest: "abc",
          network_genesis: null,
        },
      }),
    } as unknown as DeDiClient;
    const result = await checkRegistryAnchor(makeCredential("did:key:z6Mkfoo"), mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toMatch(/anchored on CORD/i);
    expect(result.detail).not.toMatch(/on network/i);
  });

  it("fails advisory when the record has no proof block", async () => {
    // Record found but DeDi did not return an anchor proof. Surface as
    // failed-advisory so the UI can show "no anchor info" without
    // rejecting the credential (the headline VALID/INVALID is unaffected).
    const mockClient = {
      resolveKey: vi.fn().mockResolvedValue({
        keyId: didKeyVm,
        controllerDid: "did:key:z6Mkfoo",
        algorithm: "Ed25519",
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
        purpose: ["assertionMethod"],
        status: "active",
      }),
    } as unknown as DeDiClient;
    const result = await checkRegistryAnchor(makeCredential("did:key:z6Mkfoo"), mockClient);
    expect(result.passed).toBe(false);
    expect(result.detail).toMatch(/no CORD anchor proof/i);
  });

  it("fails advisory when proof creator_did does not match issuer", async () => {
    // Mismatched creator is suspicious — DeDi is claiming this record was
    // anchored by someone other than the issuer the credential is signed
    // by. Surface clearly so verifier policy can reject if desired.
    const mockClient = {
      resolveKey: vi.fn().mockResolvedValue({
        keyId: didKeyVm,
        controllerDid: "did:key:z6Mkfoo",
        algorithm: "Ed25519",
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
        purpose: ["assertionMethod"],
        status: "active",
        proof: {
          type: "DediRecordProof2026",
          namespace_did: "did:cord:ns:example",
          creator_did: "did:key:z6Mkattacker",
          digest: "abc",
          network_genesis: null,
        },
      }),
    } as unknown as DeDiClient;
    const result = await checkRegistryAnchor(makeCredential("did:key:z6Mkfoo"), mockClient);
    expect(result.passed).toBe(false);
    expect(result.detail).toMatch(/does not match/i);
    expect(result.detail).toContain("did:key:z6Mkattacker");
    expect(result.detail).toContain("did:key:z6Mkfoo");
  });

  it("passes (silently) on DeDi 404 — no record published yet", async () => {
    const mockClient = {
      resolveKey: vi.fn().mockRejectedValue(new DeDiClientError("DeDi API error: 404", 404)),
    } as unknown as DeDiClient;
    const result = await checkRegistryAnchor(makeCredential("did:key:z6Mkfoo"), mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toBeUndefined();
  });

  it("passes on DeDi outage with descriptive detail", async () => {
    // Non-404 failure: pass with an "anchor status unknown" detail so the
    // UI can render rotation/anchor status as unknown without blocking
    // verification of a cryptographically valid credential.
    const mockClient = {
      resolveKey: vi.fn().mockRejectedValue(new DeDiClientError("network timeout", 502)),
    } as unknown as DeDiClient;
    const result = await checkRegistryAnchor(makeCredential("did:key:z6Mkfoo"), mockClient);
    expect(result.passed).toBe(true);
    expect(result.detail).toMatch(/anchor status unknown/i);
  });
});
