import { test, expect } from "@playwright/test";
import { mockApiResponses, navigateToTab } from "./helpers";

test.describe("Onboarding", () => {
  test.beforeEach(async ({ page }) => {
    await mockApiResponses(page);
    await page.goto("/");
    await navigateToTab(page, "Onboarding");
  });

  test("shows two onboarding type tabs and Type A info banner", async ({ page }) => {
    await expect(page.getByText("Issuers with an existing DSC", { exact: false })).toBeVisible();
    await expect(page.getByText("Type B (Domain)")).toBeVisible();
    await expect(page.getByText("Type D (Business VC)")).toBeVisible();
  });

  test.describe("Type B — Domain Verification", () => {

    test("shows domain input and verification method options", async ({ page }) => {
      await expect(page.getByText("Type B onboarding: Verify domain ownership")).toBeVisible();
      await expect(page.getByLabel("Domain")).toBeVisible();
      await expect(page.getByText("DNS TXT Record", { exact: true })).toBeVisible();
      await expect(page.getByText("HTTP Challenge", { exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "Request Challenge" })).toBeVisible();
    });

    test("request challenge button disabled when domain is empty", async ({ page }) => {
      await expect(page.getByRole("button", { name: "Request Challenge" })).toBeDisabled();
    });

    test("enter domain and request challenge — see challenge info", async ({ page }) => {
      await page.getByLabel("Domain").fill("example.com");

      await page.getByRole("button", { name: "Request Challenge" }).click();

      // Should show challenge created
      await expect(page.getByText("Challenge Created")).toBeVisible();
      await expect(page.getByText("opencred-verify=e2etoken")).toBeVisible();
      await expect(page.getByText("Add TXT record", { exact: false })).toBeVisible();

      // Confirm button should appear
      await expect(page.getByRole("button", { name: "Confirm Verification" })).toBeVisible();
    });

    test("confirm verification — see success", async ({ page }) => {
      await page.getByLabel("Domain").fill("example.com");
      await page.getByRole("button", { name: "Request Challenge" }).click();
      await expect(page.getByText("Challenge Created")).toBeVisible();

      await page.getByRole("button", { name: "Confirm Verification" }).click();

      await expect(page.getByText("Domain verified successfully")).toBeVisible();
      await expect(page.getByText("domain-issuer")).toBeVisible();
    });
  });

  test.describe("Type D — Business VC Onboarding", () => {
    test.beforeEach(async ({ page }) => {
      await page.getByText("Type D (Business VC)").click();
    });

    test("shows business VC textarea and signing preference", async ({ page }) => {
      await expect(
        page.getByText("Type D onboarding: Upload a Business Verifiable Credential"),
      ).toBeVisible();
      await expect(page.getByLabel("Business Verifiable Credential (JSON)")).toBeVisible();
      await expect(page.getByText("Signing Preference")).toBeVisible();
      await expect(page.getByRole("button", { name: "Submit Business VC" })).toBeVisible();
      await expect(page.getByText("Upload JSON File")).toBeVisible();
    });

    test("submit button disabled when textarea is empty", async ({ page }) => {
      await expect(page.getByRole("button", { name: "Submit Business VC" })).toBeDisabled();
    });

    test("paste business VC and submit — see delegation info", async ({ page }) => {
      const businessVc = JSON.stringify(
        {
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          type: ["VerifiableCredential", "BusinessCredential"],
          issuer: "did:key:zAuth",
          credentialSubject: {
            name: "Acme Corp",
            registrationNumber: "REG-12345",
          },
        },
        null,
        2,
      );

      await page.getByLabel("Business Verifiable Credential (JSON)").fill(businessVc);

      await page.getByRole("button", { name: "Submit Business VC" }).click();

      // Should show onboarding success with delegation details
      await expect(page.getByText("Onboarding successful")).toBeVisible();
      await expect(page.getByText("del-e2e")).toBeVisible();
      await expect(page.getByText("bvc-issuer")).toBeVisible();
      await expect(page.getByText("education")).toBeVisible();
      await expect(page.getByText("Save your Delegation ID")).toBeVisible();
    });

    test("signing preference defaults to delegated and can be changed", async ({ page }) => {
      await expect(page.getByText("Delegated Signing").first()).toBeVisible();
      await expect(page.getByText("Interface Signing").first()).toBeVisible();

      // Click Interface Signing
      await page.locator("label").filter({ hasText: "Interface Signing" }).last().click();
    });
  });
});
