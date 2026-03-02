import { describe, it, expect, vi } from "vitest";
import {
  checkDates,
  checkRevocation,
  checkBitstringStatusList,
  _isPrivateIP,
  _validateStatusListUrl,
  MAX_COMPRESSED_SIZE,
} from "../checks.js";
import type { DeDiClient } from "@opencred/dedi-client";
import { gzipSync } from "node:zlib";

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
      queryRevocationHash: vi.fn().mockResolvedValue({ hash: "abc", revoked: false }),
    } as unknown as DeDiClient;

    const result = await checkRevocation({ id: "test" }, mockClient);
    expect(result.passed).toBe(true);
    expect(result.name).toBe("revocation");
  });

  it("should fail when credential is revoked", async () => {
    const mockClient = {
      queryRevocationHash: vi.fn().mockResolvedValue({
        hash: "abc",
        revoked: true,
        revokedAt: "2026-06-01T00:00:00Z",
      }),
    } as unknown as DeDiClient;

    const result = await checkRevocation({ id: "test" }, mockClient);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("revoked");
    expect(result.detail).toContain("2026-06-01T00:00:00Z");
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

describe("isPrivateIP", () => {
  it("should detect IPv4 private ranges", () => {
    expect(_isPrivateIP("10.0.0.1")).toBe(true);
    expect(_isPrivateIP("10.255.255.255")).toBe(true);
    expect(_isPrivateIP("172.16.0.1")).toBe(true);
    expect(_isPrivateIP("172.31.255.255")).toBe(true);
    expect(_isPrivateIP("192.168.0.1")).toBe(true);
    expect(_isPrivateIP("192.168.255.255")).toBe(true);
  });

  it("should detect loopback addresses", () => {
    expect(_isPrivateIP("127.0.0.1")).toBe(true);
    expect(_isPrivateIP("127.255.255.255")).toBe(true);
  });

  it("should detect link-local addresses", () => {
    expect(_isPrivateIP("169.254.0.1")).toBe(true);
  });

  it("should detect CGNAT range", () => {
    expect(_isPrivateIP("100.64.0.1")).toBe(true);
    expect(_isPrivateIP("100.127.255.255")).toBe(true);
  });

  it("should detect multicast and reserved ranges", () => {
    expect(_isPrivateIP("224.0.0.1")).toBe(true);
    expect(_isPrivateIP("240.0.0.1")).toBe(true);
    expect(_isPrivateIP("255.255.255.255")).toBe(true);
  });

  it("should allow public IPv4 addresses", () => {
    expect(_isPrivateIP("8.8.8.8")).toBe(false);
    expect(_isPrivateIP("1.1.1.1")).toBe(false);
    expect(_isPrivateIP("203.0.113.1")).toBe(false);
  });

  it("should detect IPv6 loopback and unspecified", () => {
    expect(_isPrivateIP("::1")).toBe(true);
    expect(_isPrivateIP("::")).toBe(true);
  });

  it("should detect IPv6 link-local and ULA", () => {
    expect(_isPrivateIP("fe80::1")).toBe(true);
    expect(_isPrivateIP("fc00::1")).toBe(true);
    expect(_isPrivateIP("fd00::1")).toBe(true);
  });

  it("should detect IPv4-mapped IPv6 private addresses", () => {
    expect(_isPrivateIP("::ffff:127.0.0.1")).toBe(true);
    expect(_isPrivateIP("::ffff:10.0.0.1")).toBe(true);
  });

  it("should treat malformed IPv4 addresses as private", () => {
    expect(_isPrivateIP("999.999.999.999")).toBe(true);
    expect(_isPrivateIP("1.2.3.999")).toBe(true);
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
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

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
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

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
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

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
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

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

  it("should pass redirect: 'error' option to fetch", async () => {
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
    const fetchSpy = vi.fn().mockResolvedValue(mockResponse);
    vi.stubGlobal("fetch", fetchSpy);

    await checkBitstringStatusList({
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://example.com/status/1",
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ redirect: "error" }),
    );

    vi.unstubAllGlobals();
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
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

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
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

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
      { didResolver: mockResolver as any },
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
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

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
