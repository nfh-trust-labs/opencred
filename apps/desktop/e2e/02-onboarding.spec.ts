/**
 * E2E: Onboarding wizard — both DSC import and Quick Start workflows.
 */

import { test, expect, waitForAppReady } from "./electron-fixture";

test.describe("Onboarding Wizard", () => {
  test("step 1: Welcome screen → Get Started", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    await expect(page.locator("text=Welcome to OpenCred")).toBeVisible();
    await expect(page.locator("text=Your private keys never leave this machine")).toBeVisible();

    await page.click("button:has-text('Get Started')");
    await expect(page.locator("text=How would you like to get started")).toBeVisible();
  });

  test("step 2: DSC Check — shows both workflow options", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await page.click("button:has-text('Get Started')");

    await expect(page.locator("text=I have a DSC")).toBeVisible();
    await expect(page.locator("text=Quick Start")).toBeVisible();
    await expect(page.locator("text=Import your PFX or PEM certificate file")).toBeVisible();
    await expect(page.locator("text=Generate a key and verify your domain")).toBeVisible();
  });

  test("DSC workflow: back navigation works", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await page.click("button:has-text('Get Started')");
    await page.click("text=I have a DSC");

    await expect(page.locator("text=Import your Digital Signature Certificate")).toBeVisible();

    await page.click("button:has-text('Back')");
    await expect(page.locator("text=How would you like to get started")).toBeVisible();

    await page.click("button:has-text('Back')");
    await expect(page.locator("text=Welcome to OpenCred")).toBeVisible();
  });

  test("DSC workflow: Import DSC page shows password field and import button", async ({
    openCredPage: page,
  }) => {
    await waitForAppReady(page);
    await page.click("button:has-text('Get Started')");
    await page.click("text=I have a DSC");

    await expect(page.locator("text=Import your Digital Signature Certificate")).toBeVisible();
    await expect(page.locator("#pfx-password")).toBeVisible();
    await expect(page.locator("button:has-text('Choose File & Import')")).toBeVisible();

    await page.fill("#pfx-password", "test-password");
    await expect(page.locator("#pfx-password")).toHaveValue("test-password");
  });

  test("DSC workflow: P12 import shows correct description", async ({
    openCredPage: page,
  }) => {
    await waitForAppReady(page);
    await page.click("button:has-text('Get Started')");
    await page.click("text=I have a DSC");

    await expect(
      page.locator("text=Select a PFX (.pfx, .p12) or PEM (.pem, .crt) file"),
    ).toBeVisible();
    await expect(
      page.locator("text=The private key stays on this machine and is never transmitted"),
    ).toBeVisible();
  });

  test("Quick Start workflow: key generation step appears", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await page.click("button:has-text('Get Started')");
    await page.click("text=Quick Start");

    await expect(page.locator("h2:has-text('Generate Signing Key')")).toBeVisible({
      timeout: 5_000,
    });
  });

  test("step indicator shows progress dots", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    const dots = page.locator('[aria-label^="Step"]');
    const dotCount = await dots.count();
    expect(dotCount).toBeGreaterThan(0);

    await expect(dots.first()).toHaveAttribute("aria-label", /current/);
  });
});
