import { test, expect } from "@playwright/test";
import { mockApiResponses, SAMPLE_JWK } from "./helpers";

test.describe("Credential Builder (Issue Credential)", () => {
  test.beforeEach(async ({ page }) => {
    await mockApiResponses(page);
    await page.goto("/");
  });

  test("shows schema selector and signing mode options", async ({ page }) => {
    await expect(page.getByLabel("Credential Type")).toBeVisible();
    await expect(page.getByText("Interface Signing (local key)")).toBeVisible();
    await expect(page.getByText("Delegated Signing")).toBeVisible();
  });

  test("selecting a schema shows form fields", async ({ page }) => {
    await page.getByLabel("Credential Type").selectOption("education");

    // Education Credential fields
    await expect(page.getByLabel("Name", { exact: false })).toBeVisible();
    await expect(page.getByLabel("Degree", { exact: false })).toBeVisible();
    await expect(page.getByLabel("Institution", { exact: false })).toBeVisible();
    await expect(page.getByLabel("Date Conferred", { exact: false })).toBeVisible();
  });

  test("interface signing mode shows issuer DID, revocation URL, and key import", async ({
    page,
  }) => {
    // Interface signing should be selected by default
    await expect(page.getByLabel("Issuer DID")).toBeVisible();
    await expect(page.getByLabel("Revocation Registry URL")).toBeVisible();
    await expect(page.getByLabel("Signing Key (ECDSA P-256 JWK", { exact: false })).toBeVisible();
  });

  test("switching to delegated mode shows delegation ID field and hides interface fields", async ({
    page,
  }) => {
    // Click Delegated Signing radio
    await page.getByText("Delegated Signing").click();

    // Delegation ID should appear
    await expect(page.getByLabel("Delegation ID")).toBeVisible();

    // Interface fields should be hidden
    await expect(page.getByLabel("Issuer DID")).not.toBeVisible();
    await expect(
      page.getByLabel("Signing Key (ECDSA P-256 JWK", { exact: false }),
    ).not.toBeVisible();
  });

  test("delegated signing flow — build and issue credential", async ({ page }) => {
    // Select schema
    await page.getByLabel("Credential Type").selectOption("education");

    // Switch to delegated mode
    await page.getByText("Delegated Signing").click();

    // Enter delegation ID
    await page.getByLabel("Delegation ID").fill("test-delegation-123");

    // Fill required fields
    await page.locator("#field-name").fill("Alice Smith");
    await page.locator("#field-degree").fill("BSc Computer Science");
    await page.locator("#field-institution").fill("MIT");
    await page.locator("#field-dateConferred").fill("2024-06-15");

    // Click issue button
    await page.getByRole("button", { name: "Issue Credential (Delegated)" }).click();

    // Should show success
    await expect(page.getByText("Credential issued successfully")).toBeVisible();

    // Download and Issue Another buttons should appear
    await expect(page.getByRole("button", { name: "Download JSON" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Issue Another" })).toBeVisible();
  });

  test("Issue Another button resets the form", async ({ page }) => {
    // Complete a delegated issuance first
    await page.getByLabel("Credential Type").selectOption("education");
    await page.getByText("Delegated Signing").click();
    await page.getByLabel("Delegation ID").fill("test-delegation-123");
    await page.locator("#field-name").fill("Alice Smith");
    await page.locator("#field-degree").fill("BSc Computer Science");
    await page.locator("#field-institution").fill("MIT");
    await page.locator("#field-dateConferred").fill("2024-06-15");
    await page.getByRole("button", { name: "Issue Credential (Delegated)" }).click();
    await expect(page.getByText("Credential issued successfully")).toBeVisible();

    // Click Issue Another
    await page.getByRole("button", { name: "Issue Another" }).click();

    // Form should be visible again
    await expect(page.getByLabel("Credential Type")).toBeVisible();
  });

  test("interface signing shows Build & Sign button when form is valid", async ({ page }) => {
    await page.getByLabel("Credential Type").selectOption("education");

    // Fill form fields
    await page.locator("#field-name").fill("Bob Jones");
    await page.locator("#field-degree").fill("MSc Physics");
    await page.locator("#field-institution").fill("Stanford");
    await page.locator("#field-dateConferred").fill("2024-09-01");

    // Fill issuer DID
    await page
      .getByLabel("Issuer DID")
      .fill("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

    // Import key
    await page.getByLabel("Signing Key (ECDSA P-256 JWK", { exact: false }).fill(SAMPLE_JWK);
    await page.getByRole("button", { name: "Import Key" }).click();
    await expect(page.getByText("Key imported")).toBeVisible();

    // Build & Sign button should be enabled
    const buildBtn = page.getByRole("button", { name: "Build & Sign Credential" });
    await expect(buildBtn).toBeEnabled();
  });

  test("valid from and valid until date fields are present", async ({ page }) => {
    await expect(page.getByLabel("Valid From")).toBeVisible();
    await expect(page.getByLabel("Valid Until (optional)")).toBeVisible();
  });

  test("all five schema types are available", async ({ page }) => {
    const select = page.getByLabel("Credential Type");

    // Check each option exists
    await expect(select.locator("option", { hasText: "Education Credential" })).toBeAttached();
    await expect(select.locator("option", { hasText: "Employment Credential" })).toBeAttached();
    await expect(select.locator("option", { hasText: "Identity Credential" })).toBeAttached();
    await expect(select.locator("option", { hasText: "Health Credential" })).toBeAttached();
    await expect(select.locator("option", { hasText: "Business Credential" })).toBeAttached();
  });
});
