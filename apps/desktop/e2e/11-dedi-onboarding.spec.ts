/**
 * E2E: DeDi onboarding workflows — connect, skip, "not yet", and error paths.
 */

import { test, expect, waitForAppReady, skipOnboardingToDeDi } from "./electron-fixture";

test.describe("DeDi Onboarding", () => {
  test("full DeDi setup via self-published keys path", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    // Navigate: Welcome → Get Started → Self-Published Keys
    await page.click("button:has-text('Get Started')");
    await page.click("text=Self-Published Keys");

    // Generate key step
    await page.waitForSelector("h2:has-text('Generate Signing Key')", {
      timeout: 5_000,
    });
    const generateBtn = page.locator("button:has-text('Generate Key')");
    if (await generateBtn.isVisible()) {
      await generateBtn.click();
    }

    // Fill domain
    const domainInput = page.locator('input[placeholder*="domain"], input[name="domain"]');
    if (await domainInput.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await domainInput.fill("example.com");
    }

    // Click through to DeDi setup step
    for (let i = 0; i < 5; i++) {
      const dediVisible = await page
        .locator("text=Public Directory")
        .isVisible()
        .catch(() => false);
      if (dediVisible) break;

      const continueBtn = page
        .locator("button:has-text('Continue')")
        .or(page.locator("button:has-text('Next')"))
        .or(page.locator("button:has-text('Complete')"))
        .first();
      if (await continueBtn.isVisible().catch(() => false)) {
        await continueBtn.click();
        await page.waitForTimeout(500);
      } else {
        break;
      }
    }

    // Should be on the DeDi setup step
    await expect(page.locator("text=Public Directory")).toBeVisible({
      timeout: 5_000,
    });

    // Choose "Yes, I have a DeDi account"
    await page.click('button:has-text("Yes, I have a DeDi account")');

    // Verify the configure form appears
    await expect(page.locator("text=Connect to DeDi").first()).toBeVisible({
      timeout: 3_000,
    });

    // Namespace should be pre-filled with domain from self-pub path
    const nsInput = page.locator('input[placeholder*="your-domain"]');
    if (await nsInput.isVisible().catch(() => false)) {
      const nsValue = await nsInput.inputValue();
      // May be pre-filled with "example.com" from the domain step
      if (!nsValue) {
        await nsInput.fill("example.com");
      }
    }

    // Fill API key
    await page
      .locator('input[type="password"][placeholder*="DeDi API key"]')
      .fill("dk_test_e2e_key");

    // Click Connect to DeDi
    await page.click('button:has-text("Connect to DeDi")');

    // Verify success screen
    await expect(page.locator("text=DeDi Connected")).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.locator("text=3 registries created")).toBeVisible();
    await expect(page.locator("text=Published")).toBeVisible();

    // Click Continue to OpenCred
    await page.click('button:has-text("Continue to OpenCred")');

    // Verify lands on home page
    await expect(page.locator('role=tab[name="Issue"]')).toBeVisible({
      timeout: 10_000,
    });
  });

  test("full DeDi setup via DSC path", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    // Navigate: Welcome → Get Started → I have a DSC
    await page.click("button:has-text('Get Started')");
    await page.click("text=I have a DSC");

    // Import DSC — fill password and trigger import via IPC mock
    await page.waitForSelector("text=Import your Digital Signature Certificate", {
      timeout: 5_000,
    });
    await page.fill("#pfx-password", "test-password");

    // Trigger file import via IPC mock (inject a file path)
    await page.evaluate(async () => {
      // Simulate choosing a file by directly calling importKey
      const result = await window.opencred.importKey({
        filePath: "/tmp/test.pem",
        label: "DSC Test Key",
        password: "test-password",
      });
      if (result.success && result.key) {
        window.opencred._keys.push(result.key);
      }
    });

    // Click through to profile/DeDi step
    for (let i = 0; i < 6; i++) {
      const dediVisible = await page
        .locator("text=Public Directory")
        .isVisible()
        .catch(() => false);
      if (dediVisible) break;

      const btn = page
        .locator("button:has-text('Continue')")
        .or(page.locator("button:has-text('Next')"))
        .or(page.locator("button:has-text('Complete')"))
        .or(page.locator("button:has-text('Choose File & Import')"))
        .first();
      if (await btn.isVisible().catch(() => false)) {
        await btn.click();
        await page.waitForTimeout(500);
      } else {
        break;
      }
    }

    // On DeDi step — choose "Yes"
    const publicDir = page.locator("text=Public Directory");
    if (await publicDir.isVisible().catch(() => false)) {
      await page.click('button:has-text("Yes, I have a DeDi account")');

      // Namespace should be empty (no domain from DSC path)
      const nsInput = page.locator('input[placeholder*="your-domain"]');
      if (await nsInput.isVisible().catch(() => false)) {
        const nsValue = await nsInput.inputValue();
        expect(nsValue).toBeFalsy();
        await nsInput.fill("my-org.example.com");
      }

      // Fill API key and connect
      await page
        .locator('input[type="password"][placeholder*="DeDi API key"]')
        .fill("dk_test_dsc_key");
      await page.click('button:has-text("Connect to DeDi")');

      // Verify success and continue
      await expect(page.locator("text=DeDi Connected")).toBeVisible({
        timeout: 5_000,
      });
      await page.click('button:has-text("Continue to OpenCred")');
    }

    // Verify lands on home page
    await expect(page.locator('role=tab[name="Issue"]')).toBeVisible({
      timeout: 10_000,
    });
  });

  test("skip DeDi goes directly to home", async ({ openCredPage: page }) => {
    await skipOnboardingToDeDi(page);

    // Assert the DeDi step is visible — skipOnboardingToDeDi should navigate here
    await expect(page.locator("text=Public Directory")).toBeVisible({
      timeout: 5_000,
    });
    await page.click('button:has-text("Skip")');

    // Verify lands on home page
    await expect(page.locator('role=tab[name="Issue"]')).toBeVisible({
      timeout: 10_000,
    });
  });

  test('"Not yet" shows info card then skip', async ({ openCredPage: page }) => {
    await skipOnboardingToDeDi(page);

    // Assert the DeDi step is visible
    await expect(page.locator("text=Public Directory")).toBeVisible({
      timeout: 5_000,
    });

    // Click "Not yet"
    await page.click('button:has-text("Not yet")');

    // Should show info card with link to publish.dedi.global
    await expect(
      page.locator("text=publish.dedi.global").or(page.locator("text=dedi")),
    ).toBeVisible({ timeout: 3_000 });

    // Click "Skip for now"
    const skipBtn = page
      .locator('button:has-text("Skip for now")')
      .or(page.locator('button:has-text("Skip")'));
    await skipBtn.first().click();

    // Verify lands on home page
    await expect(page.locator('role=tab[name="Issue"]')).toBeVisible({
      timeout: 10_000,
    });
  });

  test("DeDi config failure shows error and allows retry", async ({ openCredPage: page }) => {
    await skipOnboardingToDeDi(page);

    const publicDir = page.locator("text=Public Directory");
    if (!(await publicDir.isVisible().catch(() => false))) {
      // If DeDi step isn't visible, skip this test
      test.skip();
      return;
    }

    // Override dediSetConfig to fail
    await page.evaluate(() => {
      window.opencred.dediSetConfig = async () => ({
        success: false,
        error: "Invalid API key",
        registriesReady: false,
      });
    });

    // Click "Yes" and fill form
    await page.click('button:has-text("Yes, I have a DeDi account")');
    const nsInput = page.locator('input[placeholder*="your-domain"]');
    if (await nsInput.isVisible().catch(() => false)) {
      await nsInput.fill("fail-test.example.com");
    }
    await page.locator('input[type="password"][placeholder*="DeDi API key"]').fill("dk_bad_key");
    await page.click('button:has-text("Connect to DeDi")');

    // Verify error message is shown
    await expect(
      page.locator("text=Invalid API key").or(page.locator(".text-red-600")),
    ).toBeVisible({ timeout: 5_000 });

    // Verify the form is still visible (can retry)
    await expect(page.locator('button:has-text("Connect to DeDi")')).toBeVisible();
  });

  test("DID publish failure shows amber warning but continues", async ({ openCredPage: page }) => {
    await skipOnboardingToDeDi(page);

    const publicDir = page.locator("text=Public Directory");
    if (!(await publicDir.isVisible().catch(() => false))) {
      test.skip();
      return;
    }

    // Override dediPublishDID to fail
    await page.evaluate(() => {
      window.opencred.dediPublishDID = async () => ({
        success: false,
        error: "Network error",
      });
    });

    // Click "Yes" and fill form
    await page.click('button:has-text("Yes, I have a DeDi account")');
    const nsInput = page.locator('input[placeholder*="your-domain"]');
    if (await nsInput.isVisible().catch(() => false)) {
      await nsInput.fill("publish-fail.example.com");
    }
    await page.locator('input[type="password"][placeholder*="DeDi API key"]').fill("dk_test_key");
    await page.click('button:has-text("Connect to DeDi")');

    // Should reach success screen
    await expect(page.locator("text=DeDi Connected")).toBeVisible({
      timeout: 5_000,
    });

    // Should show amber warning about DID publish failure
    await expect(page.locator("text=DID could not be published")).toBeVisible();

    // Continue button should still work
    await page.click('button:has-text("Continue to OpenCred")');
    await expect(page.locator('role=tab[name="Issue"]')).toBeVisible({
      timeout: 10_000,
    });
  });
});
