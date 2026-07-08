/**
 * E2E: App launch, first-run detection, and basic navigation.
 */

import { test, expect, waitForAppReady, skipOnboarding } from "./electron-fixture";

test.describe("App Launch", () => {
  test("shows the onboarding wizard on first run (no keys)", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    const title = page.locator("text=Welcome to OpenCred");
    await expect(title).toBeVisible({ timeout: 10_000 });

    const getStartedBtn = page.locator("button", { hasText: "Get Started" });
    await expect(getStartedBtn).toBeVisible();
  });

  test("shows the main tabbed interface when keys exist", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    await expect(page.locator('role=tab[name="Issue"]')).toBeVisible();
    await expect(page.locator('role=tab[name="Verify"]')).toBeVisible();
    await expect(page.locator('role=tab[name="Batch"]')).toBeVisible();
    await expect(page.locator('role=tab[name="Settings"]')).toBeVisible();

    await expect(page.locator('role=tab[name="Issue"]')).toHaveAttribute("aria-selected", "true");
  });

  test("displays online/offline indicator in header", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const statusIndicator = page.locator("header").locator("text=/Online|Offline/");
    await expect(statusIndicator).toBeVisible();
  });

  test("shows footer with version", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const footer = page.locator("footer");
    await expect(footer).toContainText("OpenCred Desktop v0.1.0");
  });

  test("navigates between tabs", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    await page.click('role=tab[name="Verify"]');
    await expect(page.locator("h2:has-text('Verify Credential')")).toBeVisible();

    await page.click('role=tab[name="Batch"]');
    await expect(page.locator("h2:has-text('Batch Credential Issuance')")).toBeVisible();

    await page.click('role=tab[name="Settings"]');
    await expect(page.locator("h2:has-text('Key Management')")).toBeVisible();

    await page.click('role=tab[name="Issue"]');
    await expect(page.locator("h2:has-text('Credential Type')")).toBeVisible();
  });
});
