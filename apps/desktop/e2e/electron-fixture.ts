/**
 * Playwright fixture for testing the OpenCred desktop renderer.
 *
 * Strategy: Since Electron's Mach port rendezvous requires OS-level
 * permissions that may not be available in all environments, we test
 * using two complementary approaches:
 *
 * 1. **Browser-based UI testing**: Launch the Vite dev server and test
 *    the renderer in a regular browser with IPC mocked via window.opencred.
 *
 * 2. **Electron-based testing**: When available (OPENCRED_E2E_ELECTRON=1),
 *    launch the real Electron app for full IPC round-trip testing.
 *
 * The browser approach covers all UI interactions, navigation, form
 * validation, and visual states. The Electron approach additionally
 * tests real IPC, signing, and file operations.
 */

import {
  test as base,
  expect,
  type Page,
  type BrowserContext,
} from "@playwright/test";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DESKTOP_ROOT = path.resolve(__dirname, "..");
const PROJECT_ROOT = path.resolve(DESKTOP_ROOT, "..", "..");

export type TestFixtures = {
  openCredPage: Page;
};

/**
 * IPC mock — a minimal simulation of window.opencred that lets us test
 * the renderer without the Electron main process.
 */
const IPC_MOCK_SCRIPT = `
window.opencred = {
  _keys: [],
  _schemas: ['education', 'employment', 'identity', 'health', 'business'],
  _revocationQueue: [],
  _config: {},
  _signedCredentials: [],

  // Key management
  async listKeys() {
    return { keys: this._keys };
  },
  async generateKey({ label }) {
    const id = 'did:key:z6Mktest' + Math.random().toString(36).slice(2, 10);
    const key = {
      id,
      fingerprint: 'SHA256:' + Math.random().toString(36).slice(2, 18),
      algorithm: 'ECDSA P-256',
      importedAt: new Date().toISOString(),
      label: label || 'Generated Key',
      format: 'generated',
      source: 'generated',
    };
    this._keys.push(key);
    return { success: true, key };
  },
  async importKey({ filePath, label, password }) {
    if (filePath && filePath.endsWith('.p12') && !password) {
      return { success: false, error: 'PFX import requires a password' };
    }
    const id = 'did:key:z6Mkimport' + Math.random().toString(36).slice(2, 10);
    const key = {
      id,
      fingerprint: 'SHA256:' + Math.random().toString(36).slice(2, 18),
      algorithm: 'ECDSA P-256',
      importedAt: new Date().toISOString(),
      label: label || 'Imported Key',
      format: filePath?.endsWith('.p12') ? 'pfx' : 'pem',
      source: 'file',
    };
    this._keys.push(key);
    return { success: true, key };
  },

  // Schema
  async listSchemas() {
    return { schemas: this._schemas };
  },
  async getSchema({ schemaId }) {
    const schemas = {
      education: {
        id: 'education',
        schema: {
          type: 'object',
          required: ['name', 'degreeType', 'institution'],
          properties: {
            name: { type: 'string' },
            degreeType: { type: 'string' },
            institution: { type: 'string' },
            dateConferred: { type: 'string', format: 'date' },
            gpa: { type: 'number' },
          },
        },
        contextUrl: 'https://schema.org/EducationalOccupationalCredential',
      },
      employment: {
        id: 'employment',
        schema: {
          type: 'object',
          required: ['employeeName', 'employer', 'position'],
          properties: {
            employeeName: { type: 'string' },
            employer: { type: 'string' },
            position: { type: 'string' },
            startDate: { type: 'string', format: 'date' },
            endDate: { type: 'string', format: 'date' },
          },
        },
        contextUrl: 'https://schema.org/EmploymentCredential',
      },
      identity: {
        id: 'identity',
        schema: {
          type: 'object',
          required: ['fullName', 'dateOfBirth'],
          properties: {
            fullName: { type: 'string' },
            dateOfBirth: { type: 'string', format: 'date' },
            nationality: { type: 'string' },
            documentNumber: { type: 'string' },
          },
        },
        contextUrl: 'https://schema.org/IdentityCredential',
      },
      health: {
        id: 'health',
        schema: {
          type: 'object',
          required: ['patientName', 'condition'],
          properties: {
            patientName: { type: 'string' },
            condition: { type: 'string' },
            diagnosisDate: { type: 'string', format: 'date' },
            provider: { type: 'string' },
          },
        },
        contextUrl: 'https://schema.org/HealthCredential',
      },
      business: {
        id: 'business',
        schema: {
          type: 'object',
          required: ['businessName', 'registrationNumber'],
          properties: {
            businessName: { type: 'string' },
            registrationNumber: { type: 'string' },
            jurisdiction: { type: 'string' },
            incorporationDate: { type: 'string', format: 'date' },
          },
        },
        contextUrl: 'https://schema.org/BusinessCredential',
      },
    };
    return schemas[schemaId] || schemas.education;
  },

  // Signing
  async signCredential({ keyId, unsignedCredential }) {
    const parsed = JSON.parse(unsignedCredential);
    parsed.proof = {
      type: 'DataIntegrityProof',
      cryptosuite: 'ecdsa-jcs-2019',
      verificationMethod: keyId,
      proofPurpose: 'assertionMethod',
      created: new Date().toISOString(),
      proofValue: 'z' + Math.random().toString(36).slice(2, 50),
    };
    return { success: true, signedCredential: JSON.stringify(parsed) };
  },
  async buildAndSign({ schemaId, issuerDid, credentialSubject, validFrom, validUntil, keyId }) {
    const credential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: issuerDid,
      validFrom: validFrom || new Date().toISOString(),
      validUntil: validUntil,
      credentialSubject: { ...credentialSubject, id: 'did:example:subject' },
      proof: {
        type: 'DataIntegrityProof',
        cryptosuite: 'ecdsa-jcs-2019',
        verificationMethod: keyId,
        proofPurpose: 'assertionMethod',
        created: new Date().toISOString(),
        proofValue: 'z' + Math.random().toString(36).slice(2, 50),
      },
    };
    this._signedCredentials.push(credential);
    return { success: true, signedCredential: JSON.stringify(credential) };
  },

  // Verification
  async verifyCredential({ credential }) {
    try {
      const parsed = JSON.parse(credential);
      if (!parsed.proof) {
        return { success: true, valid: false, message: 'No proof found', checks: [{ name: 'signature', passed: false, detail: 'No proof' }] };
      }
      // Simulate: valid if has proof with proofValue
      const hasValidProof = parsed.proof && parsed.proof.proofValue;
      const checks = [
        { name: 'signature', passed: hasValidProof, detail: hasValidProof ? undefined : 'Invalid signature' },
        { name: 'not-before', passed: true },
      ];
      if (parsed.validUntil) {
        const expired = new Date(parsed.validUntil) < new Date();
        checks.push({ name: 'expiry', passed: !expired, detail: expired ? 'Credential has expired' : undefined });
      }
      const allPassed = checks.every(c => c.passed);
      return {
        success: true,
        valid: allPassed,
        message: allPassed ? 'Credential signature is valid.' : (checks.find(c => !c.passed)?.detail || 'Verification failed.'),
        checks,
      };
    } catch (e) {
      return { success: false, error: 'Invalid JSON input: the credential is not valid JSON.' };
    }
  },

  // Packaging
  async packageCredential({ credential, formats }) {
    const outputs = formats.map(fmt => ({
      format: fmt,
      data: fmt === 'pdf' ? btoa('mock-pdf-data') : credential,
      mimeType: fmt === 'pdf' ? 'application/pdf' : 'application/json',
      suggestedFileName: 'credential.' + (fmt === 'pdf' ? 'pdf' : 'json'),
    }));
    return { success: true, outputs };
  },

  // Revocation
  async queueRevocation({ credentialId, registryUrl, reason }) {
    const item = {
      queueId: 'q-' + Math.random().toString(36).slice(2, 8),
      credentialId,
      registryUrl,
      reason,
      status: 'pending',
      queuedAt: new Date().toISOString(),
      attemptCount: 0,
    };
    this._revocationQueue.push(item);
    return { success: true, item };
  },
  async getRevocationStatus() {
    return { items: this._revocationQueue };
  },
  async publishRevocations() {
    const results = this._revocationQueue.map(item => {
      item.status = 'published';
      item.lastAttemptAt = new Date().toISOString();
      item.attemptCount = (item.attemptCount || 0) + 1;
      return { queueId: item.queueId, success: true };
    });
    return { results };
  },

  // Batch — realistic mock with CSV parsing and progress simulation
  _batch: null,
  _batchPollCount: 0,
  _batchCancelled: false,
  async batchStart({ csvContent, schemaId, keyId, columnMapping }) {
    // Parse CSV content realistically
    const lines = csvContent.split(/\\r?\\n/).filter(l => l.trim().length > 0);
    if (lines.length === 0) {
      return { success: false, error: 'CSV file is empty.' };
    }

    const headerLine = lines[0];
    const delimiter = headerLine.includes('\\t') ? '\\t' : headerLine.includes(';') ? ';' : ',';
    const headers = headerLine.split(delimiter).map(h => h.trim().replace(/^"|"$/g, ''));
    const dataLines = lines.slice(1);

    // Enforce row limit of 1000
    if (dataLines.length > 1000) {
      return { success: false, error: 'Row limit exceeded: maximum 1000 rows per batch.' };
    }

    const totalCount = dataLines.length;
    const parseErrors = [];
    let validCount = 0;
    let invalidCount = 0;

    // Simulate validation — rows with empty required fields are invalid
    const rows = dataLines.map((line, idx) => {
      const values = line.split(delimiter).map(v => v.trim().replace(/^"|"$/g, ''));
      const hasEmptyRequired = values.some(v => v === '' || v === 'INVALID');
      if (hasEmptyRequired) {
        invalidCount++;
        parseErrors.push({
          rowIndex: idx,
          errors: [{ field: headers[values.indexOf('')] || 'unknown', message: 'Required field is empty' }],
        });
        return { rowIndex: idx, status: 'skipped', error: 'Validation failed' };
      }
      validCount++;
      return { rowIndex: idx, status: 'pending' };
    });

    this._batch = {
      total: totalCount,
      validCount,
      invalidCount,
      rows,
      headers,
      schemaId,
      keyId,
    };
    this._batchPollCount = 0;
    this._batchCancelled = false;

    return {
      success: true,
      headers,
      validCount,
      invalidCount,
      totalCount,
      parseErrors: parseErrors.length > 0 ? parseErrors : undefined,
    };
  },
  async batchStatus() {
    if (!this._batch) {
      return { total: 0, completed: 0, successCount: 0, errorCount: 0, skippedCount: 0, running: false, cancelled: false, rows: [] };
    }

    this._batchPollCount++;

    if (this._batchCancelled) {
      // Mark remaining pending rows as skipped
      for (const row of this._batch.rows) {
        if (row.status === 'pending' || row.status === 'processing') {
          row.status = 'skipped';
          row.error = 'Cancelled';
        }
      }
      const completed = this._batch.rows.filter(r => r.status !== 'pending').length;
      return {
        total: this._batch.total,
        completed,
        successCount: this._batch.rows.filter(r => r.status === 'success').length,
        errorCount: this._batch.rows.filter(r => r.status === 'error').length,
        skippedCount: this._batch.rows.filter(r => r.status === 'skipped').length,
        running: false,
        cancelled: true,
        rows: this._batch.rows,
      };
    }

    // Simulate progress: process 2 rows per poll (or remaining)
    const pendingRows = this._batch.rows.filter(r => r.status === 'pending');
    const processCount = Math.min(pendingRows.length, Math.max(2, Math.ceil(this._batch.total / 3)));

    for (let i = 0; i < processCount; i++) {
      if (pendingRows[i]) {
        pendingRows[i].status = 'success';
      }
    }

    const completed = this._batch.rows.filter(r => r.status !== 'pending').length;
    const running = completed < this._batch.total;

    return {
      total: this._batch.total,
      completed,
      successCount: this._batch.rows.filter(r => r.status === 'success').length,
      errorCount: this._batch.rows.filter(r => r.status === 'error').length,
      skippedCount: this._batch.rows.filter(r => r.status === 'skipped').length,
      running,
      cancelled: false,
      rows: this._batch.rows,
    };
  },
  async batchCancel() {
    this._batchCancelled = true;
    return { success: true };
  },
  async batchExport({ outputPath } = {}) {
    if (!this._batch) {
      return { success: false, error: 'No batch results available for export.' };
    }
    const successCount = this._batch.rows.filter(r => r.status === 'success').length;
    if (successCount === 0) {
      return { success: false, error: 'No successfully issued credentials to export.' };
    }
    return {
      success: true,
      filePath: outputPath || '/tmp/mock-batch-export.zip',
      credentialCount: successCount,
      fileCount: successCount * 1, // 1 file per credential
    };
  },

  // File I/O
  async openFile({ title, filters }) {
    return { content: null, filePath: null };
  },
  async saveFile({ defaultName, content, filters, encoding }) {
    return { filePath: '/tmp/mock-save-' + defaultName };
  },

  // Network
  async getOfflineStatus() { return false; },

  // PKCS#11
  async pkcs11Detect({ libraryPath }) {
    return { exists: false, error: 'File not found (mock)' };
  },
  async pkcs11ListSlots() { return { success: false, error: 'No PKCS#11 library loaded' }; },
  async pkcs11ListKeys() { return { success: false, error: 'No session' }; },
  async pkcs11Connect() { return { success: false, error: 'Not connected' }; },

  // OS cert store
  async osCertList() {
    return {
      success: true,
      platform: 'darwin',
      storeName: 'macOS Keychain',
      certificates: [
        { id: 'mock-cert-1', subject: 'CN=Test Cert, O=E2E Test', issuer: 'CN=Test CA', validFrom: '2024-01-01', validUntil: '2025-12-31', algorithm: 'ECDSA P-256' },
      ],
    };
  },
  async osCertSign() { return { success: false, error: 'Not connected' }; },
  async osCertConnect({ certificateId, label }) {
    const id = 'did:key:z6MkoscertMock' + Math.random().toString(36).slice(2, 8);
    const key = {
      id,
      fingerprint: 'SHA256:oscert' + Math.random().toString(36).slice(2, 12),
      algorithm: 'ECDSA P-256',
      importedAt: new Date().toISOString(),
      label: label || 'OS Cert Key',
      format: 'oscert:' + certificateId,
      source: 'os-cert',
    };
    this._keys.push(key);
    return { success: true, key };
  },

  // Auto-update
  async updateCheck() { return { status: 'up-to-date' }; },
  async updateDownload() { return { status: 'up-to-date' }; },
  async updateInstall() {},
  async updateGetStatus() { return { status: 'up-to-date' }; },
  onUpdateStatus(cb) { return () => {}; },

  // Config
  async getConfig(key) { return this._config[key]; },
  async setConfig(key, value) { this._config[key] = value; },
};
`;

/**
 * Extended Playwright test with OpenCred page fixture.
 * Injects the IPC mock before each test.
 */
export const test = base.extend<TestFixtures>({
  openCredPage: async ({ page }, use) => {
    // Navigate to the Vite dev server
    const devUrl = process.env["OPENCRED_DEV_URL"] ?? "http://localhost:5174";

    // Inject the IPC mock before the page loads any scripts
    await page.addInitScript(IPC_MOCK_SCRIPT);

    await page.goto(devUrl, { waitUntil: "domcontentloaded" });

    await use(page);
  },
});

export { expect };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Wait for the app to finish its initial load and decide whether to show
 * onboarding or the main interface.
 */
export async function waitForAppReady(page: Page): Promise<void> {
  // Wait for one of the key UI elements that indicate the app has loaded.
  // Avoid page.waitForFunction() because CSP blocks eval in the renderer.
  await page
    .locator("text=Welcome to OpenCred")
    .or(page.locator('role=tab[name="Issue"]'))
    .or(page.locator("text=How would you like"))
    .first()
    .waitFor({ timeout: 15_000 });
}

/**
 * Skip onboarding by injecting a pre-populated key into the mock
 * before reload, so the app detects keys and shows the main UI.
 */
export async function skipOnboarding(page: Page): Promise<void> {
  // Add a second init script that pre-populates a key BEFORE the app checks
  await page.addInitScript(`
    // Patch: ensure _keys has at least one entry on load
    const _origListKeys = window.opencred?.listKeys;
    Object.defineProperty(window, '__opencredSkipOnboarding', { value: true, writable: false });
  `);

  // Override the IPC mock's _keys for this page's lifecycle
  await page.addInitScript(`
    if (window.opencred) {
      window.opencred._keys = [{
        id: 'did:key:z6MksetupKey12345',
        fingerprint: 'SHA256:setupkey123456789',
        algorithm: 'ECDSA P-256',
        importedAt: new Date().toISOString(),
        label: 'Setup Key',
        format: 'generated',
        source: 'generated',
      }];
    }
  `);

  await page.reload();
  await page.waitForLoadState("domcontentloaded");
  await page.waitForSelector('role=tab[name="Issue"]', { timeout: 10_000 });
}

/**
 * Generate a key via the IPC mock and return metadata.
 */
export async function generateKeyViaIpc(
  page: Page,
  label = "E2E Test Key",
): Promise<{ id: string; fingerprint: string }> {
  return page.evaluate(async (lbl: string) => {
    const resp = await window.opencred.generateKey({ label: lbl });
    if (!resp.success || !resp.key) throw new Error(resp.error ?? "Key gen failed");
    return { id: resp.key.id, fingerprint: resp.key.fingerprint };
  }, label);
}
