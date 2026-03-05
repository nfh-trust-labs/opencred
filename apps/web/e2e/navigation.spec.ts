import { test, expect } from "@playwright/test";
import { mockApiResponses } from "./helpers";

test.describe("Navigation", () => {
  test.beforeEach(async ({ page }) => {
    await mockApiResponses(page);
    await page.goto("/");
  });

  test("all six tabs are visible", async ({ page }) => {
    const tabs = [
      "Issue Credential",
      "Delegated Issuance",
      "Batch Issuance",
      "Verify",
      "Revocation",
      "Onboarding",
    ];

    for (const tabName of tabs) {
      await expect(page.getByRole("tab", { name: tabName })).toBeVisible();
    }
  });

  test("Issue Credential tab is selected by default", async ({ page }) => {
    const issueTab = page.getByRole("tab", { name: "Issue Credential" });
    await expect(issueTab).toHaveAttribute("aria-selected", "true");
  });

  test("switching between tabs shows correct content", async ({ page }) => {
    // Verify tab shows the VC JSON textarea
    await page.getByRole("tab", { name: "Verify" }).click();
    await expect(page.getByLabel("Verifiable Credential (JSON-LD or JWS)")).toBeVisible();

    // Delegated Issuance shows delegation ID input
    await page.getByRole("tab", { name: "Delegated Issuance" }).click();
    await expect(page.getByLabel("Delegation ID")).toBeVisible();

    // Batch Issuance shows CSV upload info
    await page.getByRole("tab", { name: "Batch Issuance" }).click();
    await expect(page.getByText("Upload a CSV file")).toBeVisible();

    // Revocation shows single/batch toggle
    await page.getByRole("tab", { name: "Revocation" }).click();
    await expect(page.getByText("Single Hash")).toBeVisible();

    // Onboarding shows Type A/B/D subtabs
    await page.getByRole("tab", { name: "Onboarding" }).click();
    await expect(page.getByText("Type A (DSC)")).toBeVisible();

    // Back to Issue Credential shows schema selector
    await page.getByRole("tab", { name: "Issue Credential" }).click();
    await expect(page.getByLabel("Credential Type")).toBeVisible();
  });

  test("settings panel opens and closes", async ({ page }) => {
    // Settings panel should be hidden initially
    await expect(page.getByLabel("API Base URL")).not.toBeVisible();

    // Click Settings button
    await page.getByRole("button", { name: "Settings" }).click();

    // Settings fields should be visible
    await expect(page.getByLabel("API Base URL")).toBeVisible();
    await expect(page.getByLabel("Bearer Token")).toBeVisible();

    // Click Settings again to close
    await page.getByRole("button", { name: "Settings" }).click();

    // Settings should be hidden
    await expect(page.getByLabel("API Base URL")).not.toBeVisible();
  });

  test("settings fields accept input", async ({ page }) => {
    await page.getByRole("button", { name: "Settings" }).click();

    const apiUrlInput = page.getByLabel("API Base URL");
    await apiUrlInput.clear();
    await apiUrlInput.fill("http://localhost:4000/api");
    await expect(apiUrlInput).toHaveValue("http://localhost:4000/api");

    const tokenInput = page.getByLabel("Bearer Token");
    await tokenInput.fill("my-secret-token");
    await expect(tokenInput).toHaveValue("my-secret-token");
  });
});
