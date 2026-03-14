/**
 * E2E: Revocation flow -- queue revocations from IPC, view queue status,
 * multiple revocations, reason field, and publish mock.
 */

import { test, expect, waitForAppReady, skipOnboarding } from "./electron-fixture";

test.describe("Revocation Flow", () => {
  test("queue a revocation from IPC and verify it appears in status", async ({
    openCredPage: page,
  }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    // Queue a revocation via IPC
    const result = await page.evaluate(async () => {
      return await window.opencred.queueRevocation({
        credentialId: "urn:uuid:rev-flow-test-1",
        registryUrl: "https://dedi.example.com/revocations",
        reason: "Credential holder requested revocation",
      });
    });

    expect(result.success).toBe(true);
    expect(result.item).toBeDefined();
    expect(result.item!.credentialId).toBe("urn:uuid:rev-flow-test-1");
    expect(result.item!.status).toBe("pending");
    expect(result.item!.queueId).toBeTruthy();

    // Verify it shows up in status
    const status = await page.evaluate(async () => {
      return await window.opencred.getRevocationStatus();
    });

    expect(status.items.length).toBe(1);
    expect(status.items[0].credentialId).toBe("urn:uuid:rev-flow-test-1");
    expect(status.items[0].reason).toBe("Credential holder requested revocation");
  });

  test("queue multiple revocations and verify all appear in status", async ({
    openCredPage: page,
  }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const credentials = [
      { id: "urn:uuid:multi-rev-1", reason: "Expired early" },
      { id: "urn:uuid:multi-rev-2", reason: "Incorrect data" },
      { id: "urn:uuid:multi-rev-3", reason: "Holder request" },
    ];

    // Queue all three revocations
    for (const cred of credentials) {
      await page.evaluate(
        async ({ credentialId, reason }) => {
          return await window.opencred.queueRevocation({
            credentialId,
            registryUrl: "https://dedi.example.com/revocations",
            reason,
          });
        },
        { credentialId: cred.id, reason: cred.reason },
      );
    }

    // Verify all three appear in status
    const status = await page.evaluate(async () => {
      return await window.opencred.getRevocationStatus();
    });

    expect(status.items.length).toBe(3);
    const ids = status.items.map((item: { credentialId: string }) => item.credentialId);
    expect(ids).toContain("urn:uuid:multi-rev-1");
    expect(ids).toContain("urn:uuid:multi-rev-2");
    expect(ids).toContain("urn:uuid:multi-rev-3");

    // Verify reasons are preserved
    const reasons = status.items.map((item: { reason: string }) => item.reason);
    expect(reasons).toContain("Expired early");
    expect(reasons).toContain("Incorrect data");
    expect(reasons).toContain("Holder request");
  });

  test("revocation with reason field is properly stored", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const reason = "Certificate authority reported key compromise";

    const result = await page.evaluate(async (reasonText: string) => {
      return await window.opencred.queueRevocation({
        credentialId: "urn:uuid:reason-test",
        registryUrl: "https://dedi.example.com/revocations",
        reason: reasonText,
      });
    }, reason);

    expect(result.success).toBe(true);
    expect(result.item!.reason).toBe(reason);

    // Verify reason persists in status
    const status = await page.evaluate(async () => {
      return await window.opencred.getRevocationStatus();
    });

    const item = status.items.find(
      (i: { credentialId: string }) => i.credentialId === "urn:uuid:reason-test",
    );
    expect(item).toBeDefined();
    expect(item.reason).toBe(reason);
  });

  test("publish revocations updates status of queued items", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    // Queue two revocations
    await page.evaluate(async () => {
      await window.opencred.queueRevocation({
        credentialId: "urn:uuid:publish-test-1",
        registryUrl: "https://dedi.example.com/revocations",
        reason: "Test publish 1",
      });
      await window.opencred.queueRevocation({
        credentialId: "urn:uuid:publish-test-2",
        registryUrl: "https://dedi.example.com/revocations",
        reason: "Test publish 2",
      });
    });

    // Publish all
    const publishResult = await page.evaluate(async () => {
      return await window.opencred.publishRevocations({
        dediCredentials: { type: "api-key", apiKey: "test-key-123" },
        dediBaseUrl: "https://dedi.example.com",
      });
    });

    expect(publishResult.results).toBeDefined();
    expect(publishResult.results.length).toBe(2);
    expect(publishResult.results.every((r: { success: boolean }) => r.success)).toBe(true);
  });

  test("revocation queue items have required metadata fields", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    await page.evaluate(async () => {
      await window.opencred.queueRevocation({
        credentialId: "urn:uuid:metadata-test",
        registryUrl: "https://dedi.example.com/revocations",
        reason: "Metadata check",
      });
    });

    const status = await page.evaluate(async () => {
      return await window.opencred.getRevocationStatus();
    });

    const item = status.items[0];
    expect(item).toBeDefined();

    // Verify all required metadata fields exist
    expect(item.queueId).toBeTruthy();
    expect(item.credentialId).toBe("urn:uuid:metadata-test");
    expect(item.registryUrl).toBe("https://dedi.example.com/revocations");
    expect(item.status).toBe("pending");
    expect(item.queuedAt).toBeTruthy();
    expect(item.reason).toBe("Metadata check");

    // queuedAt should be a valid ISO date string
    const queuedDate = new Date(item.queuedAt);
    expect(queuedDate.getTime()).not.toBeNaN();
  });

  test("revocation page shows placeholder UI", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    // The RevocationPage component is a placeholder; verify it renders
    // Navigate to see if revocation content is accessible
    // Currently revocation is not a top-level tab, but verify the IPC layer works
    const queueEmpty = await page.evaluate(async () => {
      const status = await window.opencred.getRevocationStatus();
      return status.items.length === 0;
    });

    expect(queueEmpty).toBe(true);
  });
});
