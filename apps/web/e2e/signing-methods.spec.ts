import { test, expect } from "@playwright/test";
import { mockApiResponses, SAMPLE_JWK } from "./helpers";

test.describe("Multi-Method Signing", () => {
  test.beforeEach(async ({ page }) => {
    await mockApiResponses(page);
    await page.goto("/");
  });

  test("shows signing method tabs in interface signing mode", async ({ page }) => {
    // Default is interface signing — signing method selector should be visible
    await expect(page.getByText("Signing Method")).toBeVisible();
    await expect(page.getByRole("button", { name: "Software Key" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Hardware Token" })).toBeVisible();
    await expect(page.getByRole("button", { name: "OS Certificate" })).toBeVisible();
  });

  test("Software Key tab is selected by default and shows JWK import", async ({ page }) => {
    // Software Key should be the active tab
    await expect(page.getByLabel("Signing Key (EC P-256/P-384", { exact: false })).toBeVisible();
  });

  test("Hardware Token and OS Certificate tabs are disabled without extension", async ({
    page,
  }) => {
    // Without the browser extension installed, these tabs should be disabled
    const hwButton = page.getByRole("button", { name: "Hardware Token" });
    const osButton = page.getByRole("button", { name: "OS Certificate" });

    await expect(hwButton).toBeDisabled();
    await expect(osButton).toBeDisabled();
  });

  test("shows extension required hint when extension is not available", async ({ page }) => {
    await expect(
      page.getByText(/Hardware Token and OS Certificate signing require/),
    ).toBeVisible();
  });

  test("hides signing method tabs in delegated signing mode", async ({ page }) => {
    await page.getByText("Delegated Signing").click();

    await expect(page.getByText("Signing Method")).not.toBeVisible();
    await expect(page.getByRole("button", { name: "Software Key" })).not.toBeVisible();
  });

  test("signing method tabs reappear when switching back to interface mode", async ({ page }) => {
    // Switch to delegated
    await page.getByText("Delegated Signing").click();
    await expect(page.getByText("Signing Method")).not.toBeVisible();

    // Switch back to interface
    await page.getByText("Interface Signing (local key)").click();
    await expect(page.getByText("Signing Method")).toBeVisible();
    await expect(page.getByRole("button", { name: "Software Key" })).toBeVisible();
  });

  test("JWK import in Software Key tab enables Build & Sign", async ({ page }) => {
    // Select schema and fill form
    await page.getByLabel("Credential Type").selectOption("education");
    await page.locator("#field-name").fill("Integration Test");
    await page.locator("#field-degree").fill("BSc");
    await page.locator("#field-institution").fill("Test University");
    await page.locator("#field-dateConferred").fill("2024-01-01");

    // Fill issuer DID
    await page.getByLabel("Issuer DID").fill("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

    // Import JWK via Software Key tab (default)
    await page.getByLabel("Signing Key (EC P-256/P-384", { exact: false }).fill(SAMPLE_JWK);
    await page.getByRole("button", { name: "Import Key" }).click();
    await expect(page.getByText("Key imported")).toBeVisible();

    // Build & Sign should be enabled
    const buildBtn = page.getByRole("button", { name: "Build & Sign Credential" });
    await expect(buildBtn).toBeEnabled();
  });

  test("full JWK signing flow produces a credential", async ({ page }) => {
    // Complete setup
    await page.getByLabel("Credential Type").selectOption("education");
    await page.locator("#field-name").fill("E2E User");
    await page.locator("#field-degree").fill("PhD");
    await page.locator("#field-institution").fill("E2E University");
    await page.locator("#field-dateConferred").fill("2024-06-15");
    await page.getByLabel("Issuer DID").fill("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

    // Import key
    await page.getByLabel("Signing Key (EC P-256/P-384", { exact: false }).fill(SAMPLE_JWK);
    await page.getByRole("button", { name: "Import Key" }).click();
    await expect(page.getByText("Key imported")).toBeVisible();

    // Build & Sign
    await page.getByRole("button", { name: "Build & Sign Credential" }).click();

    // Should show success
    await expect(page.getByText("Credential issued successfully")).toBeVisible();
    await expect(page.getByRole("button", { name: "Download JSON" })).toBeVisible();
  });
});

test.describe("Multi-Method Signing — Error Handling", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
  });

  test("shows error when API build call fails", async ({ page }) => {
    // Mock build to fail
    await page.route("**/credentials/build", async (route) => {
      await route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({
          error: { code: "INTERNAL_ERROR", message: "Build service unavailable" },
        }),
      });
    });

    // Mock package (won't be reached, but avoid unhandled routes)
    await page.route("**/credentials/package", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ credential: {}, formats: { jsonld: {} } }),
      });
    });

    // Fill form
    await page.getByLabel("Credential Type").selectOption("education");
    await page.locator("#field-name").fill("Error Test");
    await page.locator("#field-degree").fill("MSc");
    await page.locator("#field-institution").fill("Test U");
    await page.locator("#field-dateConferred").fill("2024-01-01");
    await page.getByLabel("Issuer DID").fill("did:key:z123");

    // Import key
    await page.getByLabel("Signing Key (EC P-256/P-384", { exact: false }).fill(SAMPLE_JWK);
    await page.getByRole("button", { name: "Import Key" }).click();
    await expect(page.getByText("Key imported")).toBeVisible();

    // Build & Sign — should fail
    await page.getByRole("button", { name: "Build & Sign Credential" }).click();
    await expect(page.getByText("Build service unavailable")).toBeVisible();
  });

  test("Build & Sign button is disabled when no signer is connected", async ({ page }) => {
    await mockApiResponses(page);

    // Fill form but don't import key
    await page.getByLabel("Credential Type").selectOption("education");
    await page.locator("#field-name").fill("Test");
    await page.locator("#field-degree").fill("BSc");
    await page.locator("#field-institution").fill("U");
    await page.locator("#field-dateConferred").fill("2024-01-01");
    await page.getByLabel("Issuer DID").fill("did:key:z123");

    const buildBtn = page.getByRole("button", { name: "Build & Sign Credential" });
    await expect(buildBtn).toBeDisabled();
  });
});
