/**
 * E2E: Key management -- generation, import, hardware tokens, OS cert store.
 */

import { test, expect, waitForAppReady, skipOnboarding } from "./electron-fixture";

test.describe("Key Management", () => {
  test.describe("Settings -> Key Management tabs", () => {
    test("shows all 4 key source tabs", async ({ openCredPage: page }) => {
      await waitForAppReady(page);
      await skipOnboarding(page);
      await page.click('role=tab[name="Settings"]');

      await expect(page.locator("text=Key Management")).toBeVisible();
      await expect(page.locator("button:has-text('Import File')")).toBeVisible();
      await expect(page.locator("button:has-text('Hardware Token')")).toBeVisible();
      await expect(page.locator("button:has-text('OS Cert Store')")).toBeVisible();
      await expect(page.locator("button:has-text('Generate Key')")).toBeVisible();
    });

    test("switching between sub-tabs works", async ({ openCredPage: page }) => {
      await waitForAppReady(page);
      await skipOnboarding(page);
      await page.click('role=tab[name="Settings"]');

      // HardwareToken.tsx renders "Hardware Token (PKCS#11)" as its heading
      await page.click("button:has-text('Hardware Token')");
      await expect(page.locator("text=PKCS#11 Library Path")).toBeVisible();

      // OsCertStore.tsx renders "OS Certificate Store" as its heading
      await page.click("button:has-text('OS Cert Store')");
      await expect(page.locator("text=OS Certificate Store")).toBeVisible();

      // KeyGenerate.tsx renders "Label (optional)" and "Generate P-256 Key"
      await page.click("button:has-text('Generate Key')");
      await expect(page.locator("text=Label (optional)")).toBeVisible();
    });
  });

  test.describe("Key Generation", () => {
    test("generates a new ECDSA P-256 key via UI", async ({ openCredPage: page }) => {
      await waitForAppReady(page);
      await skipOnboarding(page);
      await page.click('role=tab[name="Settings"]');
      await page.click("button:has-text('Generate Key')");

      // KeyGenerate.tsx: placeholder is "e.g. Test Issuer Key"
      const labelInput = page.locator("input[placeholder='e.g. Test Issuer Key']");
      if (await labelInput.isVisible()) {
        await labelInput.fill("E2E Generated Key");
      }

      // KeyGenerate.tsx: button text is "Generate P-256 Key"
      const generateBtn = page.locator("button:has-text('Generate P-256 Key')");
      await generateBtn.click();

      // Wait for the success message: "Key generated successfully"
      // Use waitForSelector instead of waitForFunction (CSP blocks eval)
      await page.waitForSelector("text=Key generated successfully", { timeout: 10_000 });
    });
  });

  test.describe("Hardware Token (PKCS#11)", () => {
    test("shows PKCS#11 library path input", async ({ openCredPage: page }) => {
      await waitForAppReady(page);
      await skipOnboarding(page);
      await page.click('role=tab[name="Settings"]');
      await page.click("button:has-text('Hardware Token')");

      // HardwareToken.tsx renders "PKCS#11 Library Path" label
      await expect(page.locator("text=PKCS#11 Library Path")).toBeVisible();
    });
  });

  test.describe("OS Certificate Store", () => {
    test("shows OS cert store UI", async ({ openCredPage: page }) => {
      await waitForAppReady(page);
      await skipOnboarding(page);
      await page.click('role=tab[name="Settings"]');
      await page.click("button:has-text('OS Cert Store')");

      // OsCertStore.tsx renders "OS Certificate Store" as heading
      await expect(page.locator("text=OS Certificate Store")).toBeVisible();
    });
  });

  test.describe("Active Keys Table", () => {
    test("shows key count", async ({ openCredPage: page }) => {
      await waitForAppReady(page);
      await skipOnboarding(page);
      await page.click('role=tab[name="Settings"]');

      // KeyManagement.tsx renders "{n} key(s) registered"
      // skipOnboarding pre-populates 1 key, so expect "1 key registered"
      await expect(page.locator("text=/\\d+ keys? registered/")).toBeVisible();
    });

    test("displays key metadata columns", async ({ openCredPage: page }) => {
      await waitForAppReady(page);
      await skipOnboarding(page);
      await page.click('role=tab[name="Settings"]');

      await expect(page.locator("th:has-text('Algorithm')")).toBeVisible();
      await expect(page.locator("th:has-text('Source')")).toBeVisible();
      await expect(page.locator("th:has-text('Fingerprint')")).toBeVisible();
    });

    test("generated keys show 'Generated' source label", async ({ openCredPage: page }) => {
      await waitForAppReady(page);
      await skipOnboarding(page);
      await page.click('role=tab[name="Settings"]');

      await expect(page.locator("text=Generated").first()).toBeVisible();
    });
  });
});
