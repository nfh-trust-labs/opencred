import { test, expect } from "@playwright/test";
import { mockApiResponses, navigateToTab } from "./helpers";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";

test.describe("Batch Issuance", () => {
  let csvFilePath: string;

  test.beforeEach(async ({ page }) => {
    // Create a temporary CSV file before each test that needs it
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-e2e-"));
    csvFilePath = path.join(tmpDir, "test-batch.csv");
    fs.writeFileSync(
      csvFilePath,
      "name,degree,institution,dateConferred\nAlice,BSc,MIT,2024-01-01\nBob,MSc,Stanford,2024-06-15\nCarol,PhD,Oxford,2024-09-01\n",
    );

    await mockApiResponses(page);
    await page.goto("/");
    await navigateToTab(page, "Batch Issuance");
  });

  test.afterEach(() => {
    // Clean up the temp file
    try {
      if (csvFilePath && fs.existsSync(csvFilePath)) {
        const dir = path.dirname(csvFilePath);
        fs.unlinkSync(csvFilePath);
        fs.rmdirSync(dir);
      }
    } catch {
      // Ignore cleanup errors
    }
  });

  test("shows batch issuance upload form with schema selector and signing flow", async ({
    page,
  }) => {
    await expect(page.getByText("Upload a CSV file")).toBeVisible();
    await expect(page.getByLabel("Credential Type")).toBeVisible();
    await expect(page.getByText("Delegated Signing")).toBeVisible();
    await expect(page.getByText("Interface Signing")).toBeVisible();
    await expect(page.getByText("Click to select CSV file")).toBeVisible();
  });

  test("delegated signing flow shows delegation ID field", async ({ page }) => {
    // Delegated is default
    await expect(page.getByLabel("Delegation ID")).toBeVisible();
  });

  test("switching to interface signing shows key import", async ({ page }) => {
    await page.getByText("Interface Signing").click();

    await expect(page.getByLabel("Signing Key (ECDSA P-256 JWK", { exact: false })).toBeVisible();

    // Delegation ID should not be visible
    await expect(page.getByLabel("Delegation ID")).not.toBeVisible();
  });

  test("submit button disabled without required fields", async ({ page }) => {
    // No schema selected, no file, no delegation ID
    await expect(page.getByRole("button", { name: "Submit Batch Job" })).toBeDisabled();
  });

  test("select schema, enter delegation ID, and upload CSV", async ({ page }) => {
    // Select schema
    await page.getByLabel("Credential Type").selectOption("education");

    // Enter delegation ID
    await page.getByLabel("Delegation ID").fill("batch-del-123");

    // Upload CSV via hidden file input
    const fileInput = page.locator('input[type="file"][accept=".csv"]');
    await fileInput.setInputFiles(csvFilePath);

    // File name should appear
    await expect(page.getByText("test-batch.csv")).toBeVisible();

    // Submit button should be enabled
    await expect(page.getByRole("button", { name: "Submit Batch Job" })).toBeEnabled();
  });

  test("submit batch job and see progress then results", async ({ page }) => {
    // Fill the form
    await page.getByLabel("Credential Type").selectOption("education");
    await page.getByLabel("Delegation ID").fill("batch-del-123");
    const fileInput = page.locator('input[type="file"][accept=".csv"]');
    await fileInput.setInputFiles(csvFilePath);

    // Submit
    await page.getByRole("button", { name: "Submit Batch Job" }).click();

    // Should eventually show results (mock returns completed immediately)
    await expect(page.getByText("Batch job complete")).toBeVisible({ timeout: 10000 });

    // Results should show Download and New Batch buttons
    await expect(page.getByRole("button", { name: "Download Results" })).toBeVisible();
    await expect(page.getByRole("button", { name: "New Batch" })).toBeVisible();
  });

  test("New Batch button resets the form", async ({ page }) => {
    // Complete a batch job
    await page.getByLabel("Credential Type").selectOption("education");
    await page.getByLabel("Delegation ID").fill("batch-del-123");
    const fileInput = page.locator('input[type="file"][accept=".csv"]');
    await fileInput.setInputFiles(csvFilePath);
    await page.getByRole("button", { name: "Submit Batch Job" }).click();
    await expect(page.getByText("Batch job complete")).toBeVisible({ timeout: 10000 });

    // Click New Batch
    await page.getByRole("button", { name: "New Batch" }).click();

    // Should be back at upload form
    await expect(page.getByText("Upload a CSV file")).toBeVisible();
    await expect(page.getByLabel("Credential Type")).toBeVisible();
  });
});
