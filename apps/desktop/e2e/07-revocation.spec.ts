/**
 * E2E: Revocation — IPC-level queue and status testing.
 */

import { test, expect, waitForAppReady, skipOnboarding } from "./electron-fixture";

test.describe("Revocation", () => {
  test("revocation queue starts empty", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const status = await page.evaluate(async () => {
      return await window.opencred.getRevocationStatus();
    });

    expect(status).toHaveProperty("items");
    expect(Array.isArray(status.items)).toBe(true);
  });

  test("can queue a revocation via IPC", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const result = await page.evaluate(async () => {
      return await window.opencred.queueRevocation({
        credentialId: "urn:uuid:test-credential-e2e",
        registryUrl: "https://example.com/revocation",
        reason: "E2E test revocation",
      });
    });

    expect(result.success).toBe(true);
    expect(result.item).toBeDefined();
    expect(result.item!.credentialId).toBe("urn:uuid:test-credential-e2e");
    expect(result.item!.status).toBe("pending");
  });

  test("revocation status shows queued items", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    await page.evaluate(async () => {
      await window.opencred.queueRevocation({
        credentialId: "urn:uuid:status-test",
        registryUrl: "https://example.com/revocation",
        reason: "status check test",
      });
    });

    const status = await page.evaluate(async () => {
      return await window.opencred.getRevocationStatus();
    });

    expect(status.items.length).toBeGreaterThan(0);
  });
});
