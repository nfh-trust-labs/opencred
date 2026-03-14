/**
 * E2E: Direct IPC API testing via the mocked window.opencred.
 *
 * These tests verify the renderer → IPC mock round-trip and ensure the
 * preload API surface is correctly typed and functional.
 */

import { test, expect, waitForAppReady, skipOnboarding } from "./electron-fixture";

test.describe("IPC API — Key Management", () => {
  test("listKeys returns array", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const result = await page.evaluate(async () => {
      return await window.opencred.listKeys();
    });
    expect(result).toHaveProperty("keys");
    expect(Array.isArray(result.keys)).toBe(true);
  });

  test("generateKey creates a new key", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const result = await page.evaluate(async () => {
      return await window.opencred.generateKey({ label: "IPC Test Key" });
    });

    expect(result.success).toBe(true);
    expect(result.key).toBeDefined();
    expect(result.key!.algorithm).toBe("ECDSA P-256");
    expect(result.key!.fingerprint).toBeTruthy();
    expect(result.key!.id).toMatch(/^did:key:/);
  });

  test("generated key appears in listKeys", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const genResult = await page.evaluate(async () => {
      return await window.opencred.generateKey({ label: "Listed Key" });
    });

    const listResult = await page.evaluate(async () => {
      return await window.opencred.listKeys();
    });

    const found = listResult.keys.find(
      (k: { id: string }) => k.id === genResult.key!.id,
    );
    expect(found).toBeDefined();
  });

  test("importKey rejects P12 without password", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const result = await page.evaluate(async () => {
      return await window.opencred.importKey({
        filePath: "/path/to/cert.p12",
        label: "No Password",
      });
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/password/i);
  });

  test("importKey succeeds with P12 + password", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const result = await page.evaluate(async () => {
      return await window.opencred.importKey({
        filePath: "/path/to/cert.p12",
        label: "With Password",
        password: "secret",
      });
    });
    expect(result.success).toBe(true);
    expect(result.key!.source).toBe("file");
    expect(result.key!.format).toBe("pfx");
  });
});

test.describe("IPC API — Schema", () => {
  test("listSchemas returns schema IDs", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const result = await page.evaluate(async () => {
      return await window.opencred.listSchemas();
    });

    expect(result.schemas).toContain("education");
    expect(result.schemas).toContain("employment");
    expect(result.schemas).toContain("identity");
    expect(result.schemas.length).toBeGreaterThanOrEqual(5);
  });

  test("getSchema returns schema definition with properties", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const schema = await page.evaluate(async () => {
      return await window.opencred.getSchema({ schemaId: "education" });
    });

    expect(schema.id).toBe("education");
    expect(schema.schema).toHaveProperty("properties");
    expect(schema.schema.properties).toHaveProperty("name");
    expect(schema.schema.properties).toHaveProperty("degreeType");
    expect(schema.schema.properties).toHaveProperty("institution");
  });
});

test.describe("IPC API — Build and Sign", () => {
  test("buildAndSign creates a valid VC", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    const keyResult = await page.evaluate(async () => {
      return await window.opencred.generateKey({ label: "Sign Test" });
    });

    const result = await page.evaluate(
      async (keyId: string) => {
        return await window.opencred.buildAndSign({
          schemaId: "education",
          issuerDid: keyId,
          credentialSubject: {
            name: "Alice Smith",
            degreeType: "BS Computer Science",
            institution: "MIT",
          },
          validFrom: new Date().toISOString(),
          keyId,
        });
      },
      keyResult.key!.id,
    );

    expect(result.success).toBe(true);
    const parsed = JSON.parse(result.signedCredential!);
    expect(parsed).toHaveProperty("proof");
    expect(parsed.proof).toHaveProperty("proofValue");
    expect(parsed).toHaveProperty("issuer");
    expect(parsed.credentialSubject).toHaveProperty("name", "Alice Smith");
  });
});

test.describe("IPC API — Verification", () => {
  test("verifyCredential validates a signed credential", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    // Sign a credential first
    const keyResult = await page.evaluate(async () => {
      return await window.opencred.generateKey({ label: "Verify Test" });
    });

    const signResult = await page.evaluate(
      async (keyId: string) => {
        return await window.opencred.buildAndSign({
          schemaId: "education",
          issuerDid: keyId,
          credentialSubject: { name: "Test User" },
          validFrom: new Date().toISOString(),
          keyId,
        });
      },
      keyResult.key!.id,
    );

    const verifyResult = await page.evaluate(async (cred: string) => {
      return await window.opencred.verifyCredential({ credential: cred });
    }, signResult.signedCredential!);

    expect(verifyResult.success).toBe(true);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.checks!.length).toBeGreaterThan(0);
  });

  test("verifyCredential rejects invalid JSON", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const result = await page.evaluate(async () => {
      return await window.opencred.verifyCredential({ credential: "not json" });
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/invalid.*json/i);
  });
});

test.describe("IPC API — PKCS#11", () => {
  test("pkcs11Detect reports missing library", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const result = await page.evaluate(async () => {
      return await window.opencred.pkcs11Detect({ libraryPath: "/nonexistent/lib.so" });
    });
    expect(result.exists).toBe(false);
  });
});

test.describe("IPC API — OS Certificate Store", () => {
  test("osCertList returns platform info and certificates", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const result = await page.evaluate(async () => {
      return await window.opencred.osCertList();
    });

    expect(result.success).toBe(true);
    expect(result.platform).toBe("darwin");
    expect(result.certificates!.length).toBeGreaterThan(0);
    expect(result.certificates![0]).toHaveProperty("subject");
  });

  test("osCertConnect creates a key from OS cert", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const result = await page.evaluate(async () => {
      return await window.opencred.osCertConnect({
        certificateId: "mock-cert-1",
        label: "OS Cert Key",
      });
    });

    expect(result.success).toBe(true);
    expect(result.key!.source).toBe("os-cert");
    expect(result.key!.id).toMatch(/^did:key:/);
  });
});

test.describe("IPC API — Attestation CRUD", () => {
  test("full attestation lifecycle: import → check → get → list → remove", async ({
    openCredPage: page,
  }) => {
    await waitForAppReady(page);

    const keyId = "did:key:test-attestation-key";
    const credential = JSON.stringify({
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", "KeyAttestationCredential"],
      credentialSubject: {
        id: keyId,
        organizationName: "E2E Test Corp",
        verifiedDomain: "e2e-test.example.com",
      },
      validFrom: "2024-01-01T00:00:00Z",
      validUntil: "2025-12-31T23:59:59Z",
    });

    // Import
    const importResult = await page.evaluate(
      async (args: { keyId: string; credential: string }) => {
        return await window.opencred.attestation.import(args);
      },
      { keyId, credential },
    );
    expect(importResult.success).toBe(true);
    expect(importResult.attestation!.organizationName).toBe("E2E Test Corp");

    // Check
    const checkResult = await page.evaluate(async (id: string) => {
      return await window.opencred.attestation.check({ keyId: id });
    }, keyId);
    expect(checkResult.hasAttestation).toBe(true);

    // Get
    const getResult = await page.evaluate(async (id: string) => {
      return await window.opencred.attestation.get({ keyId: id });
    }, keyId);
    expect(getResult.attestation!.keyId).toBe(keyId);
    expect(getResult.attestation!.verifiedDomain).toBe("e2e-test.example.com");

    // List
    const listResult = await page.evaluate(async () => {
      return await window.opencred.attestation.list();
    });
    expect(listResult.attestations.length).toBeGreaterThan(0);

    // Remove
    const removeResult = await page.evaluate(async (id: string) => {
      return await window.opencred.attestation.remove({ keyId: id });
    }, keyId);
    expect(removeResult.removed).toBe(true);

    // Verify removal
    const checkAfter = await page.evaluate(async (id: string) => {
      return await window.opencred.attestation.check({ keyId: id });
    }, keyId);
    expect(checkAfter.hasAttestation).toBe(false);
  });
});

test.describe("IPC API — Config", () => {
  test("get/set config round-trip", async ({ openCredPage: page }) => {
    await waitForAppReady(page);

    await page.evaluate(async () => {
      await window.opencred.setConfig("e2eTestKey", "e2eTestValue");
    });

    const value = await page.evaluate(async () => {
      return await window.opencred.getConfig("e2eTestKey");
    });

    expect(value).toBe("e2eTestValue");
  });
});

test.describe("IPC API — Network Status", () => {
  test("getOfflineStatus returns boolean", async ({ openCredPage: page }) => {
    await waitForAppReady(page);
    const isOffline = await page.evaluate(async () => {
      return await window.opencred.getOfflineStatus();
    });
    expect(typeof isOffline).toBe("boolean");
  });
});
