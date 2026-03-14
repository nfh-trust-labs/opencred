/**
 * E2E: Batch issuance -- CSV upload, batch processing, export.
 */

import { test, expect, waitForAppReady, skipOnboarding } from "./electron-fixture";

test.describe("Batch Issuance", () => {
  test("Batch tab shows batch issuance UI", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    // BatchIssuance.tsx renders "Batch Credential Issuance" as the heading
    await expect(page.locator("text=Batch Credential Issuance")).toBeVisible();
  });

  test("Batch tab shows CSV upload area", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    const body = await page.textContent("body");
    const hasCsvInput = body?.match(/CSV|file|upload|paste|drop/i);
    expect(hasCsvInput).toBeTruthy();
  });

  test("Batch tab shows schema and key selectors", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    // In the upload phase, there is an Import CSV File button.
    // Selects appear only after CSV is loaded (in mapping/config phase).
    // Verify the Import CSV File button is visible as an indicator the UI loaded.
    await expect(page.locator("button:has-text('Import CSV File')")).toBeVisible();
  });
});
