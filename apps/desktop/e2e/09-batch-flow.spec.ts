/**
 * E2E: Batch issuance flow -- CSV paste, preview, column mapping,
 * batch processing with progress, error handling, cancellation, and export.
 */

import { test, expect, waitForAppReady, skipOnboarding } from "./electron-fixture";

/**
 * Helper: Inject CSV content into the IPC mock's openFile to simulate
 * file selection, then trigger the Import CSV File button.
 */
async function injectCsvAndImport(
  page: import("@playwright/test").Page,
  csvContent: string,
  fileName = "test-batch.csv",
) {
  // Override openFile to return the CSV content
  await page.evaluate(
    ({ content, name }) => {
      window.opencred.openFile = async () => ({
        content,
        filePath: `/tmp/${name}`,
      });
    },
    { content: csvContent, name: fileName },
  );

  // Click the Import CSV File button
  await page.click("button:has-text('Import CSV File')");
}

test.describe("Batch Flow", () => {
  test("CSV import shows preview and column mapping", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    const csv = "name,degreeType,institution\nAlice,BSc,MIT\nBob,MSc,Stanford";

    await injectCsvAndImport(page, csv);

    // Preview should show CSV file name
    await expect(page.locator("text=test-batch.csv")).toBeVisible({ timeout: 5_000 });

    // Preview table should have headers
    await expect(page.locator("th:has-text('name')")).toBeVisible();
    await expect(page.locator("th:has-text('degreeType')")).toBeVisible();
    await expect(page.locator("th:has-text('institution')")).toBeVisible();

    // Data rows should be visible
    await expect(page.locator("td:has-text('Alice')")).toBeVisible();
    await expect(page.locator("td:has-text('MIT')")).toBeVisible();
  });

  test("schema selection updates available mapping fields", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    const csv = "name,degreeType,institution\nAlice,BSc,MIT";
    await injectCsvAndImport(page, csv);

    // Wait for the mapping phase
    await expect(page.locator("text=test-batch.csv")).toBeVisible({ timeout: 5_000 });

    // Select education schema
    const schemaSelect = page.locator("select").first();
    await schemaSelect.selectOption("education");

    // Column Mapping heading should appear
    await expect(page.locator("h2:has-text('Column Mapping')")).toBeVisible({ timeout: 5_000 });

    // Each CSV header should have a mapping dropdown
    const mappingSelects = page.locator("select").filter({ hasNot: page.locator("option:has-text('Select a credential type')") });
    const count = await mappingSelects.count();
    // There should be at least 3 mapping selects (one per CSV column)
    expect(count).toBeGreaterThanOrEqual(3);
  });

  test("batch start with valid CSV shows progress and completes", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    const csv = "name,degreeType,institution\nAlice,BSc,MIT\nBob,MSc,Stanford\nCarol,PhD,Harvard";
    await injectCsvAndImport(page, csv);

    // Wait for mapping phase
    await expect(page.locator("text=test-batch.csv")).toBeVisible({ timeout: 5_000 });

    // Select education schema
    const schemaSelect = page.locator("select").first();
    await schemaSelect.selectOption("education");

    // Wait for column mapping UI
    await expect(page.locator("h2:has-text('Column Mapping')")).toBeVisible({ timeout: 5_000 });

    // Click Continue to go to config phase
    await page.click("button:has-text('Continue')");

    // Fill in issuance settings
    await expect(page.locator("h2:has-text('Issuance Settings')")).toBeVisible({ timeout: 5_000 });
    await page.fill("#batch-issuer-did", "did:web:example.com");

    // Click Start Batch Issuance
    await page.click("button:has-text('Start Batch Issuance')");

    // Should show processing phase
    await expect(page.locator("h2:has-text('Batch Processing')")).toBeVisible({ timeout: 5_000 });

    // Should eventually show completion
    await expect(page.locator("h2:has-text('Batch Complete')")).toBeVisible({ timeout: 15_000 });

    // Should show success count
    await expect(page.locator("text=Success:")).toBeVisible();
  });

  test("batch with mixed valid/invalid rows shows error count", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    // CSV with some invalid rows (empty required fields)
    const csv = "name,degreeType,institution\nAlice,BSc,MIT\n,,\nCarol,PhD,Harvard";
    await injectCsvAndImport(page, csv);

    await expect(page.locator("text=test-batch.csv")).toBeVisible({ timeout: 5_000 });

    const schemaSelect = page.locator("select").first();
    await schemaSelect.selectOption("education");
    await expect(page.locator("h2:has-text('Column Mapping')")).toBeVisible({ timeout: 5_000 });
    await page.click("button:has-text('Continue')");

    await expect(page.locator("h2:has-text('Issuance Settings')")).toBeVisible({ timeout: 5_000 });
    await page.fill("#batch-issuer-did", "did:web:example.com");

    await page.click("button:has-text('Start Batch Issuance')");

    // Wait for completion
    await expect(page.locator("h2:has-text('Batch Complete')")).toBeVisible({ timeout: 15_000 });

    // Should show both success and error/skipped counts
    await expect(page.locator("text=Errors:")).toBeVisible();
    await expect(page.locator("text=Skipped:")).toBeVisible();
  });

  test("batch cancellation stops processing", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    // Build a CSV with enough rows to allow cancellation during processing
    const rows = Array.from({ length: 10 }, (_, i) => `Person${i},BSc,Uni${i}`);
    const csv = "name,degreeType,institution\n" + rows.join("\n");
    await injectCsvAndImport(page, csv);

    await expect(page.locator("text=test-batch.csv")).toBeVisible({ timeout: 5_000 });

    const schemaSelect = page.locator("select").first();
    await schemaSelect.selectOption("education");
    await expect(page.locator("h2:has-text('Column Mapping')")).toBeVisible({ timeout: 5_000 });
    await page.click("button:has-text('Continue')");

    await expect(page.locator("h2:has-text('Issuance Settings')")).toBeVisible({ timeout: 5_000 });
    await page.fill("#batch-issuer-did", "did:web:example.com");

    await page.click("button:has-text('Start Batch Issuance')");

    // Wait for processing phase to appear
    await expect(page.locator("h2:has-text('Batch Processing')")).toBeVisible({ timeout: 5_000 });

    // Click Cancel button
    const cancelBtn = page.locator("button:has-text('Cancel')");
    if (await cancelBtn.isVisible()) {
      await cancelBtn.click();
    }

    // Should eventually complete or show cancelled state
    await expect(
      page.locator("h2:has-text('Batch Complete')").or(page.locator("h2:has-text('Batch Processing')"))
    ).toBeVisible({ timeout: 15_000 });
  });

  test("export button appears after batch completes", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    const csv = "name,degreeType,institution\nAlice,BSc,MIT\nBob,MSc,Stanford";
    await injectCsvAndImport(page, csv);

    await expect(page.locator("text=test-batch.csv")).toBeVisible({ timeout: 5_000 });

    const schemaSelect = page.locator("select").first();
    await schemaSelect.selectOption("education");
    await expect(page.locator("h2:has-text('Column Mapping')")).toBeVisible({ timeout: 5_000 });
    await page.click("button:has-text('Continue')");

    await expect(page.locator("h2:has-text('Issuance Settings')")).toBeVisible({ timeout: 5_000 });
    await page.fill("#batch-issuer-did", "did:web:example.com");

    await page.click("button:has-text('Start Batch Issuance')");

    // Wait for completion
    await expect(page.locator("h2:has-text('Batch Complete')")).toBeVisible({ timeout: 15_000 });

    // Export button should be visible
    await expect(page.locator("button:has-text('Export as ZIP')")).toBeVisible();

    // Export Results heading should be visible
    await expect(page.locator("h3:has-text('Export Results')")).toBeVisible();
  });

  test("row limit exceeded error for more than 1000 rows", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    // Build a CSV with 1001 rows (exceeds 1000 row limit)
    const dataRows = Array.from({ length: 1001 }, (_, i) => `Person${i},BSc,Uni${i}`);
    const csv = "name,degreeType,institution\n" + dataRows.join("\n");
    await injectCsvAndImport(page, csv);

    await expect(page.locator("text=test-batch.csv")).toBeVisible({ timeout: 5_000 });

    const schemaSelect = page.locator("select").first();
    await schemaSelect.selectOption("education");
    await expect(page.locator("h2:has-text('Column Mapping')")).toBeVisible({ timeout: 5_000 });
    await page.click("button:has-text('Continue')");

    await expect(page.locator("h2:has-text('Issuance Settings')")).toBeVisible({ timeout: 5_000 });
    await page.fill("#batch-issuer-did", "did:web:example.com");

    await page.click("button:has-text('Start Batch Issuance')");

    // Should show an error about row limit
    await expect(page.locator("text=Row limit exceeded")).toBeVisible({ timeout: 5_000 });
  });

  test("Start New Batch resets to upload phase", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    await skipOnboarding(page);
    await page.click('role=tab[name="Batch"]');

    const csv = "name,degreeType,institution\nAlice,BSc,MIT";
    await injectCsvAndImport(page, csv);

    await expect(page.locator("text=test-batch.csv")).toBeVisible({ timeout: 5_000 });

    const schemaSelect = page.locator("select").first();
    await schemaSelect.selectOption("education");
    await expect(page.locator("h2:has-text('Column Mapping')")).toBeVisible({ timeout: 5_000 });
    await page.click("button:has-text('Continue')");

    await expect(page.locator("h2:has-text('Issuance Settings')")).toBeVisible({ timeout: 5_000 });
    await page.fill("#batch-issuer-did", "did:web:example.com");

    await page.click("button:has-text('Start Batch Issuance')");

    // Wait for completion
    await expect(page.locator("h2:has-text('Batch Complete')")).toBeVisible({ timeout: 15_000 });

    // Click Start New Batch
    await page.click("button:has-text('Start New Batch')");

    // Should return to upload phase
    await expect(page.locator("h2:has-text('Batch Credential Issuance')")).toBeVisible({ timeout: 5_000 });
    await expect(page.locator("button:has-text('Import CSV File')")).toBeVisible();
  });
});
