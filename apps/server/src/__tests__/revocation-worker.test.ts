import { describe, it, expect, vi } from "vitest";
import { DeDiClientError, DeDiRecordExistsError } from "@opencred/shared";
import { driveRevocationToLive, isRevocationInFlight } from "../revocation-worker.js";

const noopLogger = { info: () => {}, debug: () => {}, warn: () => {}, error: () => {} } as never;

function client(overrides: Record<string, unknown>) {
  return {
    queryRevocationHash: vi.fn(async () => ({ revoked: false })),
    publishRevocationHash: vi.fn(async () => ({ revoked: true, revokedAt: "t" })),
    ...overrides,
  } as never;
}

describe("driveRevocationToLive (#718 background worker)", () => {
  it("returns immediately when the record is already LIVE — no publish", async () => {
    const publish = vi.fn();
    const c = client({
      queryRevocationHash: vi.fn(async () => ({ revoked: true, revokedAt: "t" })),
      publishRevocationHash: publish,
    });
    await driveRevocationToLive(c, "h-live", undefined, undefined, noopLogger, { delayMs: 0 });
    expect(publish).not.toHaveBeenCalled();
  });

  it("drives the self-healing publish, then confirms LIVE", async () => {
    let live = false;
    const publish = vi.fn(async () => {
      live = true;
      return { revoked: true as const, revokedAt: "t" };
    });
    const query = vi.fn(async () => ({ revoked: live }));
    const c = client({ queryRevocationHash: query, publishRevocationHash: publish });
    await driveRevocationToLive(c, "h-drive", undefined, undefined, noopLogger, {
      delayMs: 0,
      maxAttempts: 5,
    });
    // iter1: query=false → publish (sets live) ; iter2: query=true → return
    expect(publish).toHaveBeenCalledTimes(1);
  });

  it("stops on DeDiRecordExistsError (already in the registry)", async () => {
    const publish = vi.fn(async () => {
      throw new DeDiRecordExistsError("exists", "hint", {});
    });
    const c = client({
      queryRevocationHash: vi.fn(async () => ({ revoked: false })),
      publishRevocationHash: publish,
    });
    await driveRevocationToLive(c, "h-exists", undefined, undefined, noopLogger, {
      delayMs: 0,
      maxAttempts: 5,
    });
    // One publish, then the DeDiRecordExistsError ends the loop (not 5 attempts).
    expect(publish).toHaveBeenCalledTimes(1);
  });

  it("retries past a publish timeout until the record goes LIVE", async () => {
    let live = false;
    let calls = 0;
    const publish = vi.fn(async () => {
      calls++;
      if (calls === 1) throw new DeDiClientError("DeDi API request timed out after 10000ms", 504);
      live = true; // second attempt's write lands
      return { revoked: true as const, revokedAt: "t" };
    });
    const query = vi.fn(async () => ({ revoked: live }));
    const c = client({ queryRevocationHash: query, publishRevocationHash: publish });
    await driveRevocationToLive(c, "h-timeout", undefined, undefined, noopLogger, {
      delayMs: 0,
      maxAttempts: 6,
    });
    // attempt1: publish→504; attempt2: publish→lands; attempt3: query=true→done
    expect(publish).toHaveBeenCalledTimes(2);
  });

  it("dedups concurrent drives for the same hash", async () => {
    const publish = vi.fn(async () => ({ revoked: true as const, revokedAt: "t" }));
    const query = vi.fn(async () => ({ revoked: false })); // never goes live → exhausts attempts
    const c = client({ queryRevocationHash: query, publishRevocationHash: publish });

    const p1 = driveRevocationToLive(c, "h-dedup", undefined, undefined, noopLogger, {
      delayMs: 0,
      maxAttempts: 2,
    });
    expect(isRevocationInFlight("h-dedup")).toBe(true);
    // Second call while the first is in flight is a no-op.
    const p2 = driveRevocationToLive(c, "h-dedup", undefined, undefined, noopLogger, {
      delayMs: 0,
      maxAttempts: 2,
    });
    await Promise.all([p1, p2]);
    expect(isRevocationInFlight("h-dedup")).toBe(false);
    // Only the first loop ran (2 attempts); the second was skipped entirely.
    expect(publish).toHaveBeenCalledTimes(2);
  });
});
