import { describe, it, expect, vi } from "vitest";
import { checkDates, checkRevocation, checkBitstringStatusList } from "../checks.js";
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
});
