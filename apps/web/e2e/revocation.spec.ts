import { test, expect } from "@playwright/test";
import { mockApiResponses, navigateToTab } from "./helpers";

test.describe("Revocation Hash Computation", () => {
  test.beforeEach(async ({ page }) => {
    await mockApiResponses(page);
    await page.goto("/");
    await navigateToTab(page, "Revocation");
  });

  test("shows single and batch mode toggle", async ({ page }) => {
    await expect(page.getByText("Single Hash")).toBeVisible();
    await expect(page.getByText("Batch Hashes")).toBeVisible();
  });

  test("single hash — enter hash and compute", async ({ page }) => {
    // Hash mode should be default
    const hashInput = page.getByRole("textbox", { name: "Credential Hash" });
    await expect(hashInput).toBeVisible();

    // Enter a hash
    await hashInput.fill("abc123hash");

    // Click Compute Hash
    await page.getByRole("button", { name: "Compute Hash" }).click();

    // Should show hash result with instruction text
    await expect(page.getByText("abc123hash")).toBeVisible();
    await expect(page.getByText("Publish this hash to your DeDi revocation registry")).toBeVisible();
  });

  test("single hash — compute hash button disabled when input is empty", async ({ page }) => {
    await expect(page.getByRole("button", { name: "Compute Hash" })).toBeDisabled();
  });

  test("switch input type to Credential JSON mode", async ({ page }) => {
    await page.getByRole("radio", { name: "Credential JSON" }).click();
    await expect(page.getByRole("textbox", { name: "Credential JSON" })).toBeVisible();
  });

  test("compute hash from credential JSON", async ({ page }) => {
    await page.getByRole("radio", { name: "Credential JSON" }).click();

    const vcJson = JSON.stringify({ type: ["VerifiableCredential"], proof: {} });
    await page.getByRole("textbox", { name: "Credential JSON" }).fill(vcJson);

    await page.getByRole("button", { name: "Compute Hash" }).click();

    // Should show the mock hash from the API
    await expect(page.getByText("mock-revocation-hash")).toBeVisible();
    await expect(page.getByText("Publish this hash to your DeDi revocation registry")).toBeVisible();
  });

  test("copy to clipboard button appears after hash computed", async ({ page }) => {
    const hashInput = page.getByRole("textbox", { name: "Credential Hash" });
    await hashInput.fill("test-hash");
    await page.getByRole("button", { name: "Compute Hash" }).click();

    await expect(page.getByRole("button", { name: "Copy to Clipboard" })).toBeVisible();
  });

  test("switch to batch mode — shows batch interface", async ({ page }) => {
    await page.getByText("Batch Hashes").click();

    await expect(page.getByLabelText(/credential jsons/i)).toBeVisible();
    await expect(page.getByRole("button", { name: "Compute Hashes" })).toBeVisible();
    await expect(page.getByText("Upload File")).toBeVisible();
  });

  test("batch hash computation — enter credentials and compute", async ({ page }) => {
    await page.getByText("Batch Hashes").click();

    // Enter credential JSONs as array
    const creds = JSON.stringify([{ type: "VC1" }, { type: "VC2" }]);
    await page.getByLabelText(/credential jsons/i).fill(creds);

    // Click Compute Hashes
    await page.getByRole("button", { name: "Compute Hashes" }).click();

    // Should show computed hashes
    await expect(page.getByText("Computed Hashes")).toBeVisible();
    await expect(page.getByText("hash-1")).toBeVisible();
    await expect(page.getByText("hash-2")).toBeVisible();
    await expect(page.getByText("Publish these hashes to your DeDi revocation registry")).toBeVisible();
  });

  test("batch hash — Compute Hashes disabled when textarea is empty", async ({ page }) => {
    await page.getByText("Batch Hashes").click();
    await expect(page.getByRole("button", { name: "Compute Hashes" })).toBeDisabled();
  });

  test("batch hash — copy all and export buttons appear after computation", async ({ page }) => {
    await page.getByText("Batch Hashes").click();

    const creds = JSON.stringify([{ type: "VC1" }]);
    await page.getByLabelText(/credential jsons/i).fill(creds);
    await page.getByRole("button", { name: "Compute Hashes" }).click();

    await expect(page.getByRole("button", { name: "Copy All" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Export to File" })).toBeVisible();
  });
});
