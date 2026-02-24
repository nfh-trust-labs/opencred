import { test, expect } from "@playwright/test";
import { mockApiResponses, navigateToTab } from "./helpers";

test.describe("Revocation", () => {
  test.beforeEach(async ({ page }) => {
    await mockApiResponses(page);
    await page.goto("/");
    await navigateToTab(page, "Revocation");
  });

  test("shows single and batch mode toggle", async ({ page }) => {
    await expect(page.getByText("Single Revocation")).toBeVisible();
    await expect(page.getByText("Batch Revocation")).toBeVisible();
  });

  test("single revocation by hash — enter hash and revoke", async ({ page }) => {
    // Hash mode should be default — use the text input specifically
    const hashInput = page.getByRole("textbox", { name: "Credential Hash" });
    await expect(hashInput).toBeVisible();

    // Enter a hash
    await hashInput.fill("abc123hash");

    // Click Revoke
    await page.getByRole("button", { name: "Revoke Credential" }).click();

    // Should show success
    await expect(page.getByText("Credential revoked successfully")).toBeVisible();
    await expect(page.getByText("mock-revoke-hash")).toBeVisible();
  });

  test("single revocation — revoke button disabled when input is empty", async ({ page }) => {
    await expect(page.getByRole("button", { name: "Revoke Credential" })).toBeDisabled();
  });

  test("switch input type to Credential JSON mode", async ({ page }) => {
    // Click Credential JSON radio
    await page.getByRole("radio", { name: "Credential JSON" }).click();

    // Should show textarea
    await expect(page.getByRole("textbox", { name: "Credential JSON" })).toBeVisible();
  });

  test("single revocation with credential JSON", async ({ page }) => {
    await page.getByRole("radio", { name: "Credential JSON" }).click();

    const vcJson = JSON.stringify({ type: ["VerifiableCredential"], proof: {} });
    await page.getByRole("textbox", { name: "Credential JSON" }).fill(vcJson);

    await page.getByRole("button", { name: "Revoke Credential" }).click();

    await expect(page.getByText("Credential revoked successfully")).toBeVisible();
  });

  test("switch to batch mode — shows batch interface", async ({ page }) => {
    await page.getByText("Batch Revocation").click();

    await expect(page.getByLabel("Credential Hashes (one per line)")).toBeVisible();
    await expect(page.getByRole("button", { name: "Revoke All" })).toBeVisible();
    await expect(page.getByText("Upload File")).toBeVisible();
  });

  test("batch revocation — enter hashes and revoke all", async ({ page }) => {
    await page.getByText("Batch Revocation").click();

    // Enter multiple hashes
    await page.getByLabel("Credential Hashes (one per line)").fill("h1\nh2");

    // Click Revoke All
    await page.getByRole("button", { name: "Revoke All" }).click();

    // Should show results
    await expect(page.getByText("Results")).toBeVisible();
    await expect(page.getByText("2/2")).toBeVisible();
    // Verify the hash spans in the results (using exact match to avoid textarea)
    await expect(page.getByText("h1", { exact: true })).toBeVisible();
    await expect(page.getByText("h2", { exact: true })).toBeVisible();
  });

  test("batch revocation — Revoke All disabled when textarea is empty", async ({ page }) => {
    await page.getByText("Batch Revocation").click();
    await expect(page.getByRole("button", { name: "Revoke All" })).toBeDisabled();
  });
});
