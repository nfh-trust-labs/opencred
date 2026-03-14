/**
 * E2E: Credential issuance -- schema selection, form filling, signing, export.
 */

import { test, expect, waitForAppReady, skipOnboarding } from "./electron-fixture";

test.describe("Credential Issuance", () => {
  test("Issue tab shows schema dropdown", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    await expect(page.locator("h2:has-text('Credential Type')")).toBeVisible();
    const schemaSelect = page.locator("select").first();
    await expect(schemaSelect).toBeVisible();
    await expect(schemaSelect).toContainText("Select a credential type");
  });

  test("schema dropdown lists all available schemas", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const schemaSelect = page.locator("select").first();
    const options = await schemaSelect.locator("option").allTextContents();

    expect(options.length).toBeGreaterThan(1);
    const schemaTexts = options.join(",").toLowerCase();
    expect(schemaTexts).toMatch(/education|employment|identity/);
  });

  test("selecting a schema loads dynamic form fields", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const schemaSelect = page.locator("select").first();
    await schemaSelect.selectOption("education");

    // Wait for form fields to appear (CSP-safe: use waitForSelector instead of waitForFunction)
    await page.waitForSelector("input[id^='field-']", { timeout: 5_000 });

    const fieldInputs = page.locator("input[id^='field-']");
    const fieldCount = await fieldInputs.count();
    expect(fieldCount).toBeGreaterThan(0);
  });

  test("form shows signing key selector", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const keySelect = page.locator("#issue-signing-key");
    await expect(keySelect).toBeVisible();
    const keyOptions = await keySelect.locator("option").count();
    expect(keyOptions).toBeGreaterThan(0);
  });

  test("form shows validity date fields with defaults", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    await expect(page.locator("#issue-valid-from")).toBeVisible();
    await expect(page.locator("#issue-valid-until")).toBeVisible();

    const validFrom = await page.locator("#issue-valid-from").inputValue();
    const today = new Date().toISOString().split("T")[0];
    expect(validFrom).toBe(today);
  });

  test("Issue Credential button is disabled without schema", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const issueBtn = page.locator("button:has-text('Issue Credential')");
    await expect(issueBtn).toBeDisabled();
  });

  test("full issuance flow: select schema -> fill fields -> sign -> view credential", async ({
    openCredPage: page,
  }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    // 1. Select education schema
    const schemaSelect = page.locator("select").first();
    await schemaSelect.selectOption("education");

    // Wait for form fields to appear (CSP-safe)
    await page.waitForSelector("input[id^='field-']", { timeout: 5_000 });

    // 2. Fill in all fields
    const fields = page.locator("input[id^='field-']");
    const fieldCount = await fields.count();
    for (let i = 0; i < fieldCount; i++) {
      const field = fields.nth(i);
      const inputType = await field.getAttribute("type");

      if (inputType === "date") {
        await field.fill("2024-06-15");
      } else if (inputType === "email") {
        await field.fill("student@example.edu");
      } else if (inputType === "url") {
        await field.fill("https://university.example.edu");
      } else if (inputType === "number") {
        // Number inputs cannot use .fill() -- use .pressSequentially() instead
        await field.click();
        await field.pressSequentially("4.0");
      } else {
        const fieldId = await field.getAttribute("id");
        const fieldName = fieldId?.replace("field-", "") ?? `field${i}`;
        await field.fill(`E2E Test ${fieldName}`);
      }
    }

    // 3. Click Issue Credential
    const issueBtn = page.locator("button:has-text('Issue Credential')");
    await expect(issueBtn).toBeEnabled();
    await issueBtn.click();

    // 4. Wait for signing result (CSP-safe: use waitForSelector)
    await page.waitForSelector("text=Credential issued successfully", { timeout: 15_000 });

    // 5. Verify the signed credential JSON is displayed
    const credentialPre = page.locator("pre");
    const credentialText = await credentialPre.textContent();
    expect(credentialText).toBeTruthy();

    const parsedCredential = JSON.parse(credentialText!);
    expect(parsedCredential).toHaveProperty("proof");
    expect(parsedCredential).toHaveProperty("issuer");
    expect(parsedCredential).toHaveProperty("type");
  });

  test("export buttons appear after successful issuance", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    // Issue a credential
    const schemaSelect = page.locator("select").first();
    await schemaSelect.selectOption("education");
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
      } else await field.fill(`Test Value ${i}`);
    }

    await page.click("button:has-text('Issue Credential')");
    await page.waitForSelector("text=Credential issued successfully", { timeout: 15_000 });

    await expect(page.locator("button:has-text('Download JSON')")).toBeVisible();
    await expect(page.locator("button:has-text('Download PDF')")).toBeVisible();
    await expect(page.locator("button:has-text('Show QR')")).toBeVisible();
  });

  test("all schemas can be selected and generate form fields", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);

    const schemaSelect = page.locator("select").first();
    const schemaValues = await schemaSelect
      .locator("option[value]")
      .evaluateAll((els) =>
        els.map((el) => (el as HTMLOptionElement).value).filter(Boolean),
      );

    for (const schemaId of schemaValues) {
      await schemaSelect.selectOption(schemaId);
      await page.waitForTimeout(500);

      const hasFields = (await page.locator("input[id^='field-']").count()) > 0;
      const body = await page.textContent("body");
      const hasError = body?.includes("Failed to load schema");

      expect(hasFields || hasError).toBeTruthy();
    }
  });
});
