import { Page } from "@playwright/test";

/**
 * Sample valid VC JSON for use in tests.
 */
export const SAMPLE_VC_JSON = JSON.stringify(
  {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "EducationCredential"],
    issuer: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    credentialSubject: {
      name: "Alice Smith",
      degree: "BSc Computer Science",
      institution: "MIT",
      dateConferred: "2024-06-15",
    },
    proof: {
      type: "DataIntegrityProof",
      created: "2024-06-15T00:00:00Z",
    },
  },
  null,
  2,
);

/**
 * Sample JWK for tests (P-256 key — used for form population and WebCrypto import).
 * Generated via Node.js crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).
 * This is a throwaway test key — never use in production.
 */
export const SAMPLE_JWK = JSON.stringify(
  {
    kty: "EC",
    crv: "P-256",
    x: "SRNND8DnxSXkjZFQqobxGjjr1j5ymdCGyxljtixSvqs",
    y: "iLq9jdUrLeJ2hJPlALYq8TtAoevIK-AdjA6cHs2RoxU",
    d: "o9g0xgVcxgELnHYpgyPsPDEUzYlxlNxEdRrQKEXVRvo",
  },
  null,
  2,
);

/**
 * Mock all API responses so tests run without a backend.
 * Uses Playwright route interception.
 */
export async function mockApiResponses(page: Page) {
  // Mock /credentials/build
  await page.route("**/credentials/build", async (route) => {
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        sessionId: "test-session-123",
        unsignedCredential: { type: ["VerifiableCredential"] },
        dataToSign: "dGVzdC1kYXRhLXRvLXNpZ24",
        proofConfig: { type: "DataIntegrityProof" },
      }),
    });
  });

  // Mock /credentials/package
  await page.route("**/credentials/package", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        credential: {
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          type: ["VerifiableCredential"],
          issuer: "did:key:z123",
        },
        formats: {
          jsonld: { type: "VC" },
          qr: "data:image/png;base64,iVBOR",
          pdf: "JVBER",
        },
      }),
    });
  });

  // Mock /verify
  await page.route("**/verify", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        status: "VALID",
        checks: {
          signature: { passed: true },
          expiry: { passed: true },
          revocation: { passed: true },
        },
      }),
    });
  });

  // Mock /credentials/issue-delegated
  await page.route("**/credentials/issue-delegated", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        credential: {
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          type: ["VerifiableCredential"],
          issuer: "did:key:zDelegated",
        },
        credentialHash: "mock-hash-abc",
      }),
    });
  });

  // Mock /credentials/revocation-hash (single) — must come before batch route
  await page.route("**/credentials/revocation-hash", async (route) => {
    if (route.request().url().includes("/batch")) {
      return route.fallback();
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ hash: "mock-revocation-hash" }),
    });
  });

  // Mock /credentials/revocation-hash/batch
  await page.route("**/credentials/revocation-hash/batch", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        hashes: [
          { hash: "hash-1", index: 0 },
          { hash: "hash-2", index: 1 },
        ],
      }),
    });
  });

  // Mock /credentials/batch/** (POST for submit, GET for status/results)
  await page.route("**/credentials/batch**", async (route) => {
    const method = route.request().method();
    const url = route.request().url();

    if (method === "POST" && url.includes("/csv")) {
      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          jobId: "mock-job-1",
          totalCredentials: 3,
          status: "pending",
        }),
      });
    } else if (method === "POST" && url.includes("/signatures")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          processed: 3,
          results: [
            { index: 0, status: "success", credential: { type: "VC" } },
            { index: 1, status: "success", credential: { type: "VC" } },
            { index: 2, status: "success", credential: { type: "VC" } },
          ],
        }),
      });
    } else if (method === "GET" && url.includes("/results")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          jobId: "mock-job-1",
          results: [
            { index: 0, status: "success", credential: { type: "VC" } },
            { index: 1, status: "success", credential: { type: "VC" } },
            { index: 2, status: "success", credential: { type: "VC" } },
          ],
        }),
      });
    } else if (method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          jobId: "mock-job-1",
          status: "completed",
          progress: 1,
          totalCredentials: 3,
          processedCredentials: 3,
          failedCredentials: 0,
        }),
      });
    } else {
      await route.continue();
    }
  });

  // Mock onboarding endpoints
  await page.route("**/onboarding/type-a", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ issuerId: "issuer-e2e", status: "active" }),
    });
  });

  await page.route("**/onboarding/domain-verify/confirm", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ verified: true, issuerId: "domain-issuer" }),
    });
  });

  await page.route("**/onboarding/domain-verify", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        challengeId: "ch-e2e",
        challengeType: "dns",
        challengeValue: "opencred-verify=e2etoken",
        instructions: "Add TXT record to _opencred.example.com",
      }),
    });
  });

  await page.route("**/onboarding/business-vc", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        delegationId: "del-e2e",
        issuerId: "bvc-issuer",
        capabilityToken: "cap",
        scope: ["education"],
        validFrom: "2024-01-01",
        validUntil: "2025-01-01",
      }),
    });
  });
}

/**
 * Navigate to a specific tab by clicking the tab button.
 */
export async function navigateToTab(page: Page, tabLabel: string) {
  await page.getByRole("tab", { name: tabLabel }).click();
}
