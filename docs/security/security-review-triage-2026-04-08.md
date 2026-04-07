# Security Review Triage — 2026-04-08

Triager: Team H
Review under triage: `docs/security/security-review-2026-04-07.md` (PR nfh-trust-labs/opencred#309)
Branches re-verified: `new-opencred-dev` plus the four unmerged fix branches:
- `fix/311-316-verification-trust-path` (CRITICAL-1, HIGH-4)
- `fix/312-server-auth-fail-closed` (CRITICAL-2)
- `fix/313-314-ssrf-dns-rebinding` (HIGH-1, HIGH-2)
- `fix/315-svg-renderer-xss` (HIGH-3)

This triage covers only the **medium** and **low** findings. The two critical and four high findings were filed by Team C as #311, #312, #313, #314, #315, #316 and are being remediated by separate PRs (#317–#320); they are out of scope here.

## Summary

- **9 findings triaged** (6 medium, 3 low)
- **9 confirmed** (filed as issues #327, #328, #329, #330, #331, #333, #334, #335, #336)
- **0 collateral fix** (none of the medium/low findings were incidentally closed by a high-severity patch)
- **0 false positive on re-read**
- **0 out of scope** (none belong to a deferred phase; all medium/low findings live in code present on `new-opencred-dev` today)

Notable nuance on MED-3: the SSRF fix branch `fix/313-314-ssrf-dns-rebinding` introduced a **second**, more thorough `isPrivateIP` inside `packages/verification/src/checks.ts` (covers CGNAT, multicast, reserved, IPv6 unspecified, partial fe8x) and threads it through the BitstringStatusList code path. The shared `@opencred/shared` `isPrivateIP` was **not** widened, and both `did:web` (HIGH-1 fix) and the desktop `SCHEMA_FETCH_URL` handler (HIGH-2 fix) still call the gappy shared helper. The MED-3 finding therefore remains **CONFIRMED** for the `did:web` and desktop schema-fetch paths even though it is partially mitigated for the status-list path.

Note: GitHub issue number #332 was claimed by an unrelated issue created during this triage session, hence the gap in our filed issue numbering.

## Per-finding

### MED-1: Windows CNG addon parses thumbprint hex with unchecked sscanf

**Status:** CONFIRMED

**Re-verification:** Read `packages/signing/native/windows/windows-cng.cpp:174-191` on `new-opencred-dev`. The `FindCertByThumbprint` function still calls `sscanf(thumbprint.c_str() + i * 2, "%02x", &byte)` with no character-class validation and no zero-init of `hashBytes`. Diffs of `windows-cng.cpp` against all four fix branches are empty.

**Issue:** #327

**Notes:** Defence-in-depth — small information disclosure of stack memory if a non-hex thumbprint reaches the function.

### MED-2: verifyJwsProof does not pass algorithms allowlist to compactVerify

**Status:** CONFIRMED

**Re-verification:** Read `packages/verification/src/jws-proof.ts:60-82` on `new-opencred-dev`. The call is still `await compactVerify(jwsString, publicKey)` with no `{ algorithms: [...] }` second argument. Diffs of `jws-proof.ts` against all four fix branches are empty.

**Issue:** #328

**Notes:** Defence-in-depth gap. `vc-jwt.ts` and `sd-jwt-vc.ts` both pass `algorithms: ALLOWED_ALGORITHMS` correctly; `jws-proof.ts` is the outlier.

### MED-3: isPrivateIP in @opencred/shared is missing several reserved ranges

**Status:** CONFIRMED (partially mitigated for one code path)

**Re-verification:** Read `packages/shared/src/ssrf.ts` on `fix/313-314-ssrf-dns-rebinding` (the most up-to-date version). `isPrivateIPv4` only covers `10.`, `127.`, `0.`, `169.254.`, `172.16-31.`, `192.168.`. `isPrivateIPv6` only covers `::1`, `fc`/`fd` prefixes, and the literal `fe80:` prefix (not `fe81`–`febf`). CGNAT (`100.64.0.0/10`), benchmark (`198.18.0.0/15`), TEST-NET, multicast (`224.0.0.0/4`), reserved (`240.0.0.0/4`), `255.255.255.255`, IPv6 unspecified (`::`), IPv6 multicast (`ff00::/8`), and NAT64 (`64:ff9b::/96`) are all still uncovered.

The fix branch *does* add a more thorough `isPrivateIP` to `packages/verification/src/checks.ts` (lines 96-135 post-fix; covers CGNAT, 198.18, multicast, reserved, ::, partial fe8x) and passes it as a predicate to `resolveAndPinHostname` from the BitstringStatusList check. But:

- `packages/did/src/did-web.ts` (HIGH-1 fix) imports `isPrivateIP` and `resolveAndPinHostname` from `@opencred/shared` and does NOT supply an override predicate — the shared (gappy) helper is used.
- `apps/desktop/src/main/ipc-handlers.ts` `SCHEMA_FETCH_URL` (HIGH-2 fix) does the same — imports the shared `isPrivateIP` and calls `resolveAndPinHostname(hostname)` without an override.

Net: the BitstringStatusList code path is fixed; the `did:web` resolver and the desktop schema fetch are not. The finding's recommendation to consolidate the two implementations is also unaddressed — the duplicate is now codified rather than removed.

**Issue:** #329

**Notes:** This is the only medium that was *partially* touched by the high-severity work. The fix is incomplete in two ways: (a) missing ranges in shared, (b) duplicate implementation pattern. Both are in scope of #329.

### MED-4: Logger redaction misses base64url-encoded keys

**Status:** CONFIRMED

**Re-verification:** Read `apps/desktop/src/main/logger.ts:34-45` on `new-opencred-dev`. `LONG_BASE64_RE = /(?=[A-Za-z0-9+/]*\+)[A-Za-z0-9+/]{40,}={0,3}/g` still requires a literal `+` to match, which excludes all base64url blobs. Diffs of `logger.ts` against all four fix branches are empty.

**Issue:** #330

**Notes:** Defence-in-depth gap. No call site logs raw private-key bytes today, but `signing-key-provider.ts:215` does pass through `error.message` from `loadFromPem` errors which could surface base64url chunks unredacted.

### MED-5: getConfig/setConfig IPC handlers expose any electron-store key to the renderer

**Status:** CONFIRMED

**Re-verification:** Read `apps/desktop/src/main/ipc-handlers.ts:823-839` on `new-opencred-dev`. `handleGetConfig` calls `store.get(request.key as keyof typeof store.store)` and `handleSetConfig` calls `store.set(request.key as keyof typeof store.store, request.value)` — both with no allowlist of permitted keys. Read `apps/desktop/src/main/preload.ts:258-262` — the renderer-facing API still exposes generic `getConfig(key: string)` and `setConfig(key: string, value: unknown)`.

The SVG fix branch (`fix/315-svg-renderer-xss`) modifies `apps/desktop/src/main/ipc-handlers.ts` to add new branding-related handlers but the diff does not touch `handleGetConfig`/`handleSetConfig` or their `IPC_CHANNELS.GET_CONFIG`/`SET_CONFIG` registrations.

**Issue:** #331

**Notes:** Compounds with HIGH-3 (SVG XSS). HIGH-3 is being fixed, but if any future renderer-injection path lands, this generic IPC surface lets the attacker plant a malicious `importedKeyPaths` entry that becomes a signing key on next launch.

### MED-6: DeDi HTTPS enforcement bypassed when NODE_ENV=development; no SSRF check on baseUrl

**Status:** CONFIRMED

**Re-verification:** Read `packages/dedi-client/src/api/api-client.ts:51-58` on `new-opencred-dev`. The constructor still has the env-var bypass:

```ts
if (url.protocol !== "https:" && process.env.NODE_ENV !== "development" && process.env.NODE_ENV !== "test") {
  throw new DeDiClientError("DeDi baseUrl must use HTTPS in production", 400);
}
```

There is no SSRF/private-IP check on `baseUrl`. Diffs of `api-client.ts` against all four fix branches are empty.

**Issue:** #333

**Notes:** Two distinct sub-issues bundled in one finding (env-var bypass, missing SSRF check). The recommendation in the finding handles both; #333 tracks them together.

### LOW-1: BrowserWindow runs with sandbox: false; no CSP, navigation, or window-open handlers

**Status:** CONFIRMED

**Re-verification:** Read `apps/desktop/src/main/index.ts:54-67` on `new-opencred-dev`. `webPreferences.sandbox` is still `false`. Grep on the file shows no `setWindowOpenHandler`, `will-navigate`, or `Content-Security-Policy` references. Diffs of `index.ts` against all four fix branches are empty.

**Issue:** #334

**Notes:** Hardening. No active exploit path on the renderer today (all content is local), but pairs with HIGH-3.

### LOW-2: forceCodeSigning: false in electron-builder config

**Status:** CONFIRMED

**Re-verification:** Read `apps/desktop/package.json:74-80` on `new-opencred-dev`. The `build` block still has `"forceCodeSigning": false`. Diffs of `package.json` against all four fix branches are empty.

**Issue:** #335

**Notes:** Build config. CI signs releases today, but the toggle being `false` means a misconfigured CI run can silently ship an unsigned artifact.

### LOW-3: OpenCredError does not actually sanitize messages — CLAUDE.md claim is documentation-only

**Status:** CONFIRMED

**Re-verification:** Read `packages/shared/src/errors.ts` on `new-opencred-dev`. The base `OpenCredError` class is a thin `Error` subclass that stores `message` verbatim and exposes it via `toJSON()`. No regex stripping, no path/key/PEM scrubbing. Read `packages/crypto/src/signing-key-provider.ts:210-220` — confirmed that `loadFromPem` still wraps `error.message` directly into `CryptoError` with no sanitization. Diffs of `errors.ts` against all four fix branches are empty.

**Issue:** #336

**Notes:** Either implement actual sanitisation in the hierarchy or correct the `CLAUDE.md` claim. #336 leaves the choice to the implementer.

## Cross-cutting observations

1. The high-severity fix branches focused tightly on their assigned findings and did **not** incidentally clean up adjacent medium issues. The only partial overlap was MED-3 ↔ HIGH-1/2 via the SSRF fix branch — and even there, the new thorough `isPrivateIP` lives in `checks.ts` rather than being lifted into `@opencred/shared`, so two of the three SSRF call sites still use the gappy shared helper.
2. None of the medium/low findings duplicated each other or duplicated the criticals/highs, so all 9 needed individual issues.
3. None of the medium/low findings reference Phase-6/7-only code (Cloud HSM, container CI/CD, etc.). All cited files exist and are active on `new-opencred-dev` today, so all 9 are correctly labelled `final-sprint`.

## Triage timing

All re-verifications completed on 2026-04-08 against `new-opencred-dev` HEAD plus the four fix branches at the SHAs listed above. Each finding was checked in under 10 minutes of reading; none required deeper investigation, and there are no UNVERIFIED findings.
