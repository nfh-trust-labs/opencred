import { test, expect } from "@playwright/test";
import { mockApiResponses, navigateToTab, SAMPLE_VC_JSON } from "./helpers";

test.describe("Credential Verification", () => {
  test.beforeEach(async ({ page }) => {
    await mockApiResponses(page);
    await page.goto("/");
    await navigateToTab(page, "Verify");
  });

  test("shows credential input textarea and verify button", async ({ page }) => {
    await expect(page.getByLabel("Verifiable Credential (JSON)")).toBeVisible();
    await expect(page.getByRole("button", { name: "Verify" })).toBeVisible();
    await expect(page.getByText("Upload JSON file")).toBeVisible();
  });

  test("verify button is disabled when textarea is empty", async ({ page }) => {
    await expect(page.getByRole("button", { name: "Verify" })).toBeDisabled();
  });

  test("paste credential JSON and verify — shows VALID result", async ({ page }) => {
    // Paste credential JSON
    await page.getByLabel("Verifiable Credential (JSON)").fill(SAMPLE_VC_JSON);

    // Click verify
    await page.getByRole("button", { name: "Verify" }).click();

    // Should show VALID status
    await expect(page.getByTestId("verification-status")).toHaveText("VALID");

    // Check individual verification checks header
    await expect(page.getByText("Verification Checks")).toBeVisible();

    // Check each check name appears (use the capitalize class spans within the checks section)
    const checksSection = page.locator(".space-y-4").filter({ hasText: "Verification Checks" });
    await expect(checksSection.getByText("signature")).toBeVisible();
    await expect(checksSection.getByText("expiry")).toBeVisible();
    await expect(checksSection.getByText("revocation")).toBeVisible();

    // All checks should pass
    const passes = page.getByText("Pass");
    await expect(passes.first()).toBeVisible();
  });

  test("invalid JSON shows error message", async ({ page }) => {
    await page.getByLabel("Verifiable Credential (JSON)").fill("not valid json {{{");
    await page.getByRole("button", { name: "Verify" }).click();

    await expect(page.getByText("Invalid JSON", { exact: false })).toBeVisible();
  });

  test("verify with REVOKED response shows correct status", async ({ page }) => {
    // Override the verify mock for this test
    await page.route("**/verify", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          status: "REVOKED",
          checks: {
            signature: { passed: true },
            expiry: { passed: true },
            revocation: { passed: false, detail: "Credential has been revoked" },
          },
        }),
      });
    });

    await page.getByLabel("Verifiable Credential (JSON)").fill(SAMPLE_VC_JSON);
    await page.getByRole("button", { name: "Verify" }).click();

    await expect(page.getByTestId("verification-status")).toHaveText("REVOKED");
  });

  test("verify with EXPIRED response shows correct status", async ({ page }) => {
    await page.route("**/verify", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          status: "EXPIRED",
          checks: {
            signature: { passed: true },
            expiry: { passed: false, detail: "Credential has expired" },
            revocation: { passed: true },
          },
        }),
      });
    });

    await page.getByLabel("Verifiable Credential (JSON)").fill(SAMPLE_VC_JSON);
    await page.getByRole("button", { name: "Verify" }).click();

    await expect(page.getByTestId("verification-status")).toHaveText("EXPIRED");
  });

  test("verify with DELEGATION_INVALID shows correct status", async ({ page }) => {
    await page.route("**/verify", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          status: "DELEGATION_INVALID",
          checks: {
            signature: { passed: true },
            expiry: { passed: true },
            revocation: { passed: true },
            delegation: { passed: false, detail: "Delegation expired" },
          },
        }),
      });
    });

    await page.getByLabel("Verifiable Credential (JSON)").fill(SAMPLE_VC_JSON);
    await page.getByRole("button", { name: "Verify" }).click();

    await expect(page.getByTestId("verification-status")).toHaveText("DELEGATION INVALID");
  });

  test("clearing the textarea clears the result", async ({ page }) => {
    // Verify first
    await page.getByLabel("Verifiable Credential (JSON)").fill(SAMPLE_VC_JSON);
    await page.getByRole("button", { name: "Verify" }).click();
    await expect(page.getByTestId("verification-status")).toHaveText("VALID");

    // Clear textarea — result should disappear
    await page.getByLabel("Verifiable Credential (JSON)").fill("");
    await expect(page.getByTestId("verification-status")).not.toBeVisible();
  });
});
