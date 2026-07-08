# Desktop e2e checks

Renderer-only end-to-end walks driven by Playwright against the real Vite dev
server, with `window.opencred` (the preload IPC bridge) stubbed — so the full
UI flow runs without Electron, the main process, or any network/DeDi calls.

## onboarding.e2e.cjs

Guards the plain-language onboarding redesign: the four Step-2 identity anchors,
the per-anchor publish copy ("…to your site" vs "…to your DeDi account"), the
no-skipped-step progress indicator, and the public-directory (DeDi) flow
(configure-first, prefilled namespace, account guidance, Advanced drawer).

```sh
# one-time: install the Playwright chromium browser
npx playwright install chromium

# run it (starts and stops its own Vite dev server on :5176)
pnpm --filter @opencred/desktop test:e2e
```

Not wired into CI (org Actions budget is capped); run locally before shipping
onboarding changes. Exits non-zero if any check fails.
