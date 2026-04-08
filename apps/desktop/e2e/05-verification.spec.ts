/**
 * E2E: Credential verification -- paste JSON, verify signature, check results.
 */

import { test, expect, waitForAppReady, skipOnboarding } from "./electron-fixture";
import type { Page } from "@playwright/test";

/**
 * Helper: Issue a credential and return the JSON string.
 */
async function issueCredential(page: Page): Promise<string> {
  await page.click('role=tab[name="Issue"]');
  const schemaSelect = page.locator("select").first();
  await schemaSelect.selectOption("education");

  // Wait for form fields (CSP-safe)
  await page.waitForSelector("input[id^='field-']", { timeout: 5_000 });

  const fields = page.locator("input[id^='field-']");
  const fieldCount = await fields.count();
  for (let i = 0; i < fieldCount; i++) {
    const field = fields.nth(i);
    const inputType = await field.getAttribute("type");
    if (inputType === "date") await field.fill("2024-06-15");
    else if (inputType === "number") {
      await field.click();
      await field.pressSequentially("4");
    } else await field.fill(`Verify Test ${i}`);
  }

  await page.click("button:has-text('Issue Credential')");
  await page.waitForSelector("text=Credential issued successfully", { timeout: 15_000 });

  const credentialText = await page.locator("pre").textContent();
  return credentialText!;
}

test.describe("Credential Verification", () => {
  test("Verify tab shows textarea and verify button", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Verify"]');

    await expect(page.locator("text=Verify Credential")).toBeVisible();
    await expect(page.locator("textarea")).toBeVisible();
    // Use main to scope past the nav tab button and target the page button
    await expect(page.locator("main button:has-text('Verify')")).toBeVisible();
  });

  test("Verify button is disabled with empty input", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Verify"]');

    // Scope to main to avoid matching the nav tab
    const verifyBtn = page.locator("main button:has-text('Verify')");
    await expect(verifyBtn).toBeDisabled();
  });

  test("Upload File button is visible", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Verify"]');

    await expect(page.locator("button:has-text('Upload File')")).toBeVisible();
  });

  test("round-trip: issue -> verify -> VALID", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const credentialJson = await issueCredential(page);
    await page.click('role=tab[name="Verify"]');

    await page.locator("textarea").fill(credentialJson);
    // Scope to main to click the page Verify button, not the nav tab
    await page.locator("main button:has-text('Verify')").click();

    // Wait for result (CSP-safe: use waitForSelector instead of waitForFunction)
    await page.waitForSelector("text=VALID", { timeout: 15_000 });

    await expect(page.locator("text=VALID").first()).toBeVisible();
    await expect(page.locator("text=Valid Credential")).toBeVisible();
  });

  test("verification shows per-check results", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const credentialJson = await issueCredential(page);
    await page.click('role=tab[name="Verify"]');
    await page.locator("textarea").fill(credentialJson);
    await page.locator("main button:has-text('Verify')").click();

    await page.waitForSelector("text=VALID", { timeout: 15_000 });

    await expect(page.locator("text=Verification Checks")).toBeVisible();
    // Use exact: true to match only the check name, not "Credential signature is valid."
    await expect(page.getByText("signature", { exact: true })).toBeVisible();
    await expect(page.locator("text=PASS").first()).toBeVisible();
  });

  test("invalid JSON shows error", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Verify"]');

    await page.locator("textarea").fill("not valid json {{{");
    await page.locator("main button:has-text('Verify')").click();

    // Wait for error result (CSP-safe)
    await page.locator("text=/INVALID|Invalid|failed|error/i").first().waitFor({ timeout: 10_000 });

    const body = await page.textContent("body");
    expect(body).toMatch(/invalid|error|failed/i);
  });

  test("tampered credential shows INVALID", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const credentialJson = await issueCredential(page);
    await page.click('role=tab[name="Verify"]');

    // Remove the proof to make it invalid
    const parsed = JSON.parse(credentialJson);
    delete parsed.proof;
    const tamperedJson = JSON.stringify(parsed);

    await page.locator("textarea").fill(tamperedJson);
    await page.locator("main button:has-text('Verify')").click();

    // Wait for result (CSP-safe)
    await page
      .locator("text=INVALID")
      .or(page.locator("text=VALID"))
      .first()
      .waitFor({ timeout: 15_000 });

    await expect(page.getByText("INVALID", { exact: true })).toBeVisible();
  });

  test("Clear button resets the form", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Verify"]');

    const textarea = page.locator("textarea");
    await textarea.fill('{"test": "data"}');

    const clearBtn = page.locator("button:has-text('Clear')");
    await expect(clearBtn).toBeVisible();
    await clearBtn.click();

    await expect(textarea).toHaveValue("");
  });
});
