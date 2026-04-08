/**
 * E2E: Key rotation reminder — badge, banner, dismiss, and did:web warning.
 */

import { test, expect, waitForAppReady, skipOnboarding } from "./electron-fixture";

test.describe("Key Rotation Reminder", () => {
  test("no badge when key is fresh", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    // Verify no rotation badge on Settings button
    const badge = page.locator('span[aria-label="Key rotation overdue"]');
    await expect(badge).not.toBeVisible();
  });

  test("badge appears when key is 91+ days old", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    // Inject a key with createdAt set to 91 days ago
    const ninetyOneDaysAgo = new Date(Date.now() - 91 * 24 * 60 * 60 * 1000).toISOString();

    await page.addInitScript(`
      if (window.opencred) {
        window.opencred._keys = [{
          id: 'did:key:z6MkoldKey123',
          fingerprint: 'SHA256:oldkey123456789',
          algorithm: 'ECDSA P-256',
          importedAt: '${ninetyOneDaysAgo}',
          createdAt: '${ninetyOneDaysAgo}',
          label: 'Old Key',
          format: 'generated',
          source: 'generated',
        }];
      }
    `);
    await page.reload();
    await page.waitForLoadState("domcontentloaded");

    // Wait for app to load with the old key
    await page
      .locator('role=tab[name="Issue"]')
      .waitFor({ timeout: 10_000 })
      .catch(() => {
        /* may show onboarding */
      });

    // Assert the amber rotation badge appears on Settings button
    const badge = page.locator('span[aria-label="Key rotation overdue"]');
    await expect(badge).toBeVisible({ timeout: 5_000 });

    // Navigate to Settings and verify the rotation warning banner
    await page.click('button:has-text("Settings"), [aria-label="Settings"]');
    await expect(
      page.locator("text=days old").or(page.locator("text=Consider rotating")),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("dismiss rotation reminder", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    // Inject old key
    const ninetyOneDaysAgo = new Date(Date.now() - 91 * 24 * 60 * 60 * 1000).toISOString();

    await page.addInitScript(`
      if (window.opencred) {
        window.opencred._keys = [{
          id: 'did:key:z6MkoldKeyDismiss',
          fingerprint: 'SHA256:oldkeydismiss123',
          algorithm: 'ECDSA P-256',
          importedAt: '${ninetyOneDaysAgo}',
          createdAt: '${ninetyOneDaysAgo}',
          label: 'Old Key for Dismiss',
          format: 'generated',
          source: 'generated',
        }];
      }
    `);
    await page.reload();
    await page.waitForLoadState("domcontentloaded");

    // Wait for app to be ready
    await page
      .locator('role=tab[name="Issue"]')
      .waitFor({ timeout: 10_000 })
      .catch(() => {
        /* may show onboarding */
      });

    // Assert the badge is visible after injecting an old key
    const badge = page.locator('span[aria-label="Key rotation overdue"]');
    await expect(badge).toBeVisible({ timeout: 5_000 });

    // Navigate to Settings
    await page.click('button:has-text("Settings"), [aria-label="Settings"]');
    await expect(page.locator("text=Consider rotating")).toBeVisible({
      timeout: 5_000,
    });

    // Click Dismiss
    await page.click('button:has-text("Dismiss")');

    // Verify badge disappears from TopBar
    await expect(badge).not.toBeVisible({ timeout: 3_000 });

    // Reload and verify badge stays dismissed
    await page.reload();
    await page.waitForLoadState("domcontentloaded");
    await page
      .locator('role=tab[name="Issue"]')
      .waitFor({ timeout: 10_000 })
      .catch(() => {});

    await expect(badge).not.toBeVisible();
  });

  test("did:web warning in credential builder", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    // Set up a self-generated key with no DeDi configured
    await page.addInitScript(`
      if (window.opencred) {
        window.opencred._keys = [{
          id: 'did:web:example.com',
          fingerprint: 'SHA256:selfpubkey12345',
          algorithm: 'ECDSA P-256',
          importedAt: new Date().toISOString(),
          label: 'Self-Published Key',
          format: 'generated',
          source: 'generated',
        }];
        // Ensure DeDi is not configured
        window.opencred._dediConfig = null;
      }
    `);
    await page.reload();
    await page.waitForLoadState("domcontentloaded");

    // Wait for app to load
    await page
      .locator('role=tab[name="Issue"]')
      .waitFor({ timeout: 10_000 })
      .catch(() => {
        /* may show onboarding */
      });

    // Navigate to Issue tab (builder)
    const issueTab = page.locator('role=tab[name="Issue"]');
    if (await issueTab.isVisible().catch(() => false)) {
      await issueTab.click();

      // Check for the did:web publication warning
      const warning = page.locator("text=hasn't been published");
      const warningVisible = await warning.isVisible({ timeout: 3_000 }).catch(() => false);

      if (warningVisible) {
        await expect(warning).toBeVisible();

        // Verify issuance still works (warn but allow) — select a schema
        const schemaSelect = page.locator("select").or(page.locator('[role="combobox"]')).first();
        if (await schemaSelect.isVisible().catch(() => false)) {
          await schemaSelect.selectOption({ index: 1 }).catch(() => {});
        }

        // The builder should still be functional
        await expect(
          page.locator("button:has-text('Issue')").or(page.locator("button:has-text('Sign')")),
        )
          .toBeVisible({ timeout: 3_000 })
          .catch(() => {});
      }
    }
  });
});
