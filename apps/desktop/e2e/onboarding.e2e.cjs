/**
 * Onboarding wizard end-to-end check (renderer-only, mocked IPC).
 *
 * Drives the real renderer in a headless browser with a stubbed
 * `window.opencred` so the full first-run onboarding flow can be exercised
 * without Electron, the main process, or any network/DeDi calls. Guards the
 * plain-language redesign: the four Step-2 identity anchors, the per-anchor
 * publish copy, the no-skipped-step progress indicator, and the
 * public-directory (DeDi) flow.
 *
 * Run:  pnpm --filter @opencred/desktop test:e2e
 * Requires the Playwright chromium browser once:  npx playwright install chromium
 * Not wired into CI (org Actions budget); run locally before shipping
 * onboarding changes. Self-contained — it starts and stops its own Vite dev
 * server.
 */
const { spawn } = require("node:child_process");
const path = require("node:path");
const { chromium } = require("playwright");

const PORT = 5176;
const URL = `http://localhost:${PORT}`;
const DESKTOP_DIR = path.resolve(__dirname, "..");

const results = [];
const check = (name, cond, detail = "") => {
  results.push({ name, pass: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? "  — " + detail : ""}`);
};

// Stubbed preload bridge. The renderer calls these on mount and through the
// flow; returning an empty key set forces the onboarding wizard to show.
const MOCK = () => {
  window.__exportCalls = [];
  const key = {
    id: "did:key:zMockKey#zMockKey",
    fingerprint: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    algorithm: "P-256",
    source: "software-generated",
  };
  window.opencred = {
    listKeys: async () => ({ keys: [] }),
    getOfflineStatus: async () => ({ offline: false }),
    getConfig: async () => null,
    generateKey: async () => ({ success: true, key }),
    exportDidDocument: async ({ domain }) => {
      window.__exportCalls.push(domain);
      return { success: true, did: "did:web:" + domain, didDocument: "{}" };
    },
    exportDidKeyDocument: async () => ({ success: true, didDocument: "{}" }),
    verifyDidWeb: async () => ({ accessible: true }),
    saveFile: async () => ({ filePath: "/tmp/did.json" }),
    dediSetConfig: async () => ({ success: true, registriesReady: true }),
    dediPublishKey: async () => ({ success: true, didDocumentStored: true }),
    dediEnsureRegistries: async () => ({ success: true }),
  };
};

async function activeStepLabel(page) {
  for (const label of ["Welcome", "Identity", "Your key", "Publish", "Done"]) {
    const el = page.getByText(label, { exact: true }).first();
    if ((await el.count()) === 0) continue;
    const cls = (await el.getAttribute("class")) || "";
    if (cls.includes("text-brand-blue")) return label;
  }
  return "(none)";
}

function startVite() {
  const proc = spawn(path.join(DESKTOP_DIR, "node_modules/.bin/vite"), ["--port", String(PORT)], {
    cwd: DESKTOP_DIR,
    stdio: "ignore",
  });
  return proc;
}

async function waitForServer() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(URL);
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error("Vite dev server did not start in time");
}

async function run(page) {
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));

  const gotoStep2 = async () => {
    await page.goto(URL, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /Get Started/i }).click();
    await page.getByText("Where should your issuer identity live?").waitFor({ state: "visible" });
  };

  // Welcome + Step 2
  await page.goto(URL, { waitUntil: "domcontentloaded" });
  await page.getByText("Welcome to OpenCred").waitFor({ state: "visible" });
  await page.getByRole("button", { name: /Get Started/i }).click();
  await page.getByText("Where should your issuer identity live?").waitFor({ state: "visible" });
  for (const lbl of ["Welcome", "Identity", "Your key", "Publish", "Done"]) {
    check(`indicator label "${lbl}"`, (await page.getByText(lbl, { exact: true }).count()) > 0);
  }
  for (const a of [
    "My organisation has a website",
    "Publish to a DeDi directory",
    "I have an official certificate",
    "Just get started",
  ]) {
    check(`Step 2 anchor "${a}"`, (await page.getByText(a, { exact: true }).count()) > 0);
  }
  check("Step 2 active = Identity", (await activeStepLabel(page)) === "Identity");
  const step2 = await page.locator("main").innerText();
  check("no protocol jargon on Step 2", !/did:web|did:key|did\.json|\.well-known/.test(step2));

  // Website -> publish to site (Publish active, no skip)
  await page.getByRole("button", { name: /My organisation has a website/ }).click();
  await page.getByText("Create your signing key", { exact: true }).waitFor();
  check("website: active = Your key", (await activeStepLabel(page)) === "Your key");
  await page.getByRole("button", { name: /Generate Key Pair/ }).click();
  await page.getByText("Enter your domain").waitFor();
  await page.getByPlaceholder("university.example").fill("acme.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByText("Publish your identity to your site").waitFor();
  check("website: publish-to-site title + active = Publish", (await activeStepLabel(page)) === "Publish");

  // Directory -> configure-first DeDi publish
  await gotoStep2();
  await page.getByRole("button", { name: /Publish to a DeDi directory/ }).click();
  await page.getByText("Create your signing key", { exact: true }).waitFor();
  await page.getByRole("button", { name: /Generate Key Pair/ }).click();
  await page.getByText("Enter your DeDi namespace").waitFor();
  check("directory: namespace field", (await page.getByText("DeDi namespace", { exact: true }).count()) > 0);
  await page.getByPlaceholder("acme").fill("did.cord.network:acme");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByText("Publish your identity to your DeDi account").waitFor();
  await page.getByRole("button", { name: "Continue" }).waitFor({ state: "visible" });
  check("directory: export auto-generated", (await page.getByRole("button", { name: /Generate identity document/ }).count()) === 0);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByText("Your issuer identity is ready").waitFor();
  await page.getByRole("button", { name: /Start Issuing Credentials/ }).click();
  await page.getByRole("heading", { name: "Connect to DeDi" }).waitFor();
  check("directory: DeDi opens on configure (choice skipped)", (await page.getByText("Yes, I have a DeDi account").count()) === 0);
  check("directory: namespace prefilled", (await page.locator('input[type="text"]').first().inputValue()) === "did.cord.network:acme");
  check("directory: publish.dedi.global guidance", (await page.getByRole("link", { name: /publish\.dedi\.global/ }).count()) > 0);
  check("directory: Advanced disclosure", (await page.getByText(/Advanced/i).count()) > 0);

  // did:key -> confirm screen, still "Your key"
  await gotoStep2();
  await page.getByRole("button", { name: /Just get started/ }).click();
  await page.getByText("Create your signing key", { exact: true }).waitFor();
  await page.getByRole("button", { name: /Generate Key Pair/ }).click();
  await page.getByText("Your did:key identifier").waitFor();
  check("did:key: active = Your key (no premature Publish)", (await activeStepLabel(page)) === "Your key");

  // Certificate -> DSC source
  await gotoStep2();
  await page.getByRole("button", { name: /I have an official certificate/ }).click();
  await page.getByText("How is your DSC stored?").waitFor();
  check("certificate: DSC source screen", true);

  check("no uncaught page errors", errors.length === 0, errors.join(" | "));
}

(async () => {
  const vite = startVite();
  let browser;
  try {
    await waitForServer();
    browser = await chromium.launch();
    const ctx = await browser.newContext({ viewport: { width: 920, height: 860 } });
    await ctx.addInitScript(MOCK);
    const page = await ctx.newPage();
    await run(page);
  } finally {
    if (browser) await browser.close();
    vite.kill();
  }
  const failed = results.filter((r) => !r.pass);
  console.log(`\n=== ${results.length - failed.length}/${results.length} checks passed ===`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => {
  console.error("E2E ERROR:", e);
  process.exit(2);
});
