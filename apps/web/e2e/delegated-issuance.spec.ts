import { test, expect } from "@playwright/test";
import { mockApiResponses, navigateToTab } from "./helpers";

test.describe("Delegated Issuance", () => {
  test.beforeEach(async ({ page }) => {
    await mockApiResponses(page);
    await page.goto("/");
    await navigateToTab(page, "Delegated Issuance");
  });

  test("shows delegation info and delegation ID input", async ({ page }) => {
    await expect(
      page.getByText("Delegated issuance uses an OpenCred-managed signing key"),
    ).toBeVisible();
    await expect(page.getByLabel("Delegation ID")).toBeVisible();
    await expect(page.getByRole("button", { name: "Continue" })).toBeVisible();
  });

  test("Continue button is disabled when delegation ID is empty", async ({ page }) => {
    await expect(page.getByRole("button", { name: "Continue" })).toBeDisabled();
  });

  test("entering delegation ID and clicking Continue shows the form", async ({ page }) => {
    await page.getByLabel("Delegation ID").fill("del-123");
    await page.getByRole("button", { name: "Continue" }).click();

    // Should show delegation ID in info bar
    await expect(page.getByText("del-123")).toBeVisible();

    // Schema selector should appear
    await expect(page.getByLabel("Credential Type")).toBeVisible();
  });

  test("full delegated issuance flow — issue and see result", async ({ page }) => {
    // Step 1: Enter delegation ID
    await page.getByLabel("Delegation ID").fill("del-abc-456");
    await page.getByRole("button", { name: "Continue" }).click();

    // Step 2: Select schema and fill form
    await page.getByLabel("Credential Type").selectOption("employment");

    await page.locator("#field-name").fill("Jane Doe");
    await page.locator("#field-employer").fill("Acme Corp");
    await page.locator("#field-position").fill("Engineer");
    await page.locator("#field-startDate").fill("2024-01-15");

    // Step 3: Issue
    await page.getByRole("button", { name: "Issue Credential (Delegated)" }).click();

    // Step 4: See result
    await expect(page.getByText("Credential issued via delegated signing")).toBeVisible();
    await expect(page.getByText("mock-hash-abc")).toBeVisible();
  });

  test("download button appears after issuance", async ({ page }) => {
    await page.getByLabel("Delegation ID").fill("del-test");
    await page.getByRole("button", { name: "Continue" }).click();

    await page.getByLabel("Credential Type").selectOption("education");
    await page.locator("#field-name").fill("Test User");
    await page.locator("#field-degree").fill("PhD");
    await page.locator("#field-institution").fill("Oxford");
    await page.locator("#field-dateConferred").fill("2024-06-15");

    await page.getByRole("button", { name: "Issue Credential (Delegated)" }).click();

    await expect(page.getByRole("button", { name: "Download JSON" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Issue Another" })).toBeVisible();
  });

  test("Issue Another resets back to delegation ID step", async ({ page }) => {
    // Complete issuance
    await page.getByLabel("Delegation ID").fill("del-reset");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByLabel("Credential Type").selectOption("education");
    await page.locator("#field-name").fill("Test");
    await page.locator("#field-degree").fill("BSc");
    await page.locator("#field-institution").fill("MIT");
    await page.locator("#field-dateConferred").fill("2024-01-01");
    await page.getByRole("button", { name: "Issue Credential (Delegated)" }).click();
    await expect(page.getByText("Credential issued via delegated signing")).toBeVisible();

    // Click Issue Another
    await page.getByRole("button", { name: "Issue Another" }).click();

    // Should be back at delegation ID input
    await expect(page.getByLabel("Delegation ID")).toBeVisible();
    await expect(page.getByRole("button", { name: "Continue" })).toBeVisible();
  });

  test("valid from and valid until date fields are present in form step", async ({ page }) => {
    await page.getByLabel("Delegation ID").fill("del-dates");
    await page.getByRole("button", { name: "Continue" }).click();

    await expect(page.getByLabel("Valid From")).toBeVisible();
    await expect(page.getByLabel("Valid Until (optional)")).toBeVisible();
  });
});
