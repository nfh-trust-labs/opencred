# Testing

OpenCred uses [vitest](https://vitest.dev/) across the entire monorepo. Each package has its own `vitest.config.ts`. Tests live alongside the code they test, in `src/__tests__/` directories.

## Running tests

### Everything

```bash
# Run all workspace tests once
pnpm -r test

# Or, from the root, vitest in workspace mode
pnpm test
```

The root `vitest.workspace.ts` aggregates per-package configs so a single `vitest` invocation can run everything.

### A specific package

```bash
cd packages/crypto
pnpm test                    # one-shot
pnpm vitest                  # watch mode (rerun on file change)
pnpm vitest run path/to/test # specific test file
pnpm vitest run -t "name"    # filter by test name
```

If `pnpm vitest` is not available in a package's local `node_modules`, fall back to the workspace binary:

```bash
cd packages/crypto
../../node_modules/.bin/vitest run
```

### Coverage

```bash
pnpm test:coverage
```

This runs `vitest run --coverage` from the root. Coverage targets:

| Package | Target |
|---|---|
| `packages/crypto` | 90%+ (security-critical) |
| `packages/vc-core` | 90%+ |
| `packages/verification` | 90%+ |
| `packages/did` | 85%+ |
| `packages/schema-engine` | 85%+ |
| Other packages | 80%+ |
| `apps/desktop` (main process) | 70%+ |
| `apps/desktop` (renderer) | not enforced (UI is exercised by E2E) |
| `apps/server` | 80%+ |

These are aspirational targets, not gates. CI does not currently fail PRs on coverage.

## Test layout conventions

Each package follows the same pattern:

```
packages/<name>/
  src/
    foo.ts
    bar.ts
    __tests__/
      foo.test.ts        # unit test
      foo-edge-cases.test.ts
      integration.test.ts
```

Naming conventions:

* `*.test.ts` — vitest test files
* `*-edge-cases.test.ts` — focused tests for boundary conditions, attack vectors, and regressions
* `__tests__/fixtures/` — test data
* `__tests__/helpers/` — shared test utilities

## Categories of tests

### Unit tests

The bulk of OpenCred's tests are unit tests that exercise a single module against pre-computed inputs and expected outputs.

Key vector sources:

* **W3C VC Data Integrity test vectors** — `packages/crypto` validates ECDSA-RDFC-2019 against the published W3C suite
* **NIST ECDSA P-256 test vectors** — `packages/crypto`
* **RFC 8785 JCS test data** — `packages/crypto/src/__tests__/jcs.test.ts`
* **W3C DID Core test cases** — `packages/did`

### Integration tests

Integration tests exercise multiple packages working together — for example, building a credential with `vc-core`, signing it with `crypto`, and verifying it with `verification`. These live in `apps/desktop/src/main/__tests__/` and `apps/server/src/__tests__/`.

### End-to-end tests

The Desktop client has an end-to-end smoke test (`apps/desktop/e2e-test.mjs`) that launches the packaged Electron app and exercises the onboarding wizard, key import, issuance, and verification flows. It uses Playwright under the hood.

The Docker server has its own end-to-end pattern: spin up the container with a test key, hit the endpoints with `curl` or `fetch`, and assert on responses. See `apps/server/src/__tests__/`.

### SSRF and security tests

The `did:web` SSRF protection has dedicated tests:

* `packages/shared/src/__tests__/ssrf.test.ts` — covers IPv4 ranges, IPv6 ranges, IPv4-mapped IPv6 (dotted and hex forms), edge cases like `0.0.0.0` and `::1`
* `packages/shared/src/__tests__/pinned-fetch.test.ts` — covers `fetchWithPinnedIp`, the DNS-rebinding-safe transport: the socket-level `lookup` override returns only the pinned addresses, the URL keeps the hostname for TLS validation, and every request uses a fresh non-keep-alive agent so pooled sockets can't bypass the pin
* `packages/did/src/__tests__/did-web.test.ts` — covers the resolver behaviour: HTTPS-only, no redirects, timeout, document ID match, plus a dedicated DNS-rebinding (TOCTOU) suite asserting the fetch is pinned to the validated addresses and DNS is consulted exactly once
* `apps/desktop/src/__tests__/schema-fetch-ssrf.test.ts` — the `SCHEMA_FETCH_URL` IPC handler: multi-record validation, fail-closed DNS errors, pinned fetch, and the 1 MiB response-size cap

These tests are critical — adding a new IP range or a new resolver should always come with an additional test.

The logger redaction has its own tests:

* `apps/desktop/src/main/__tests__/logger.test.ts` — verifies PEM blocks, JWK `d` fields, and long base64 strings are stripped before reaching disk

## Known flaky tests

| Test | Cause | Workaround |
|---|---|---|
| `apps/desktop` auto-updater test | `electron-updater` mock interaction | Re-run; usually passes on second attempt. Tracked in a follow-up issue. |

If you encounter a flaky test that isn't in this list, file an issue describing the failure mode and reproducer.

## Mocking

OpenCred prefers **real implementations** over mocks wherever possible. The exceptions:

* **Network calls** — DeDi HTTP calls and `did:web` fetches are mocked with `vi.mock` and a fake fetch implementation
* **Hardware tokens** — `pkcs11js` is mocked with `softhsm2` (a software PKCS#11 module) for tests that exercise the PKCS#11 path
* **Cloud HSMs** — AWS KMS, Azure Key Vault, and GCP KMS clients are mocked with their official SDK mocks
* **OS cert store** — the native addons are stubbed in tests so cross-platform tests pass

For unit tests of pure logic (canonicalization, hashing, schema validation), no mocking is needed.

## Test data and fixtures

Test fixtures live in `__tests__/fixtures/` directories within each package. Sensitive examples:

* `packages/crypto/src/__tests__/fixtures/` — test private keys (P-256, P-384, Ed25519). These are clearly labelled `TEST KEY — DO NOT USE IN PRODUCTION`.
* `packages/verification/src/__tests__/fixtures/` — sample credentials (valid, expired, tampered, revoked) for verifier tests.

The test keys are deliberately checked into the repository so tests are reproducible. They are **never** to be used in any real signing operation.

## Writing a new test

```ts
import { describe, it, expect } from "vitest";
import { CredentialBuilder } from "../credential-builder.js";

describe("CredentialBuilder", () => {
  it("requires an issuer", () => {
    expect(() => new CredentialBuilder().build()).toThrow(/issuer/i);
  });

  it("accepts a valid did:web issuer", () => {
    const credential = new CredentialBuilder()
      .setIssuer("did:web:example.com")
      .setCredentialSubject({ name: "Jane" })
      .setValidFrom("2026-04-01T00:00:00Z")
      .build();

    expect(credential.issuer).toBe("did:web:example.com");
  });
});
```

Conventions:

* `describe` blocks for the unit under test (a class, a function, a feature area)
* `it` blocks for individual behaviours, written as English assertions
* Assertions are explicit — prefer `toEqual` for objects and `toBe` for primitives
* Async tests use `async/await`, not `.then()`
* No `console.log` in committed tests — use `expect` to assert what you want to verify

## CI

CI runs on every PR via GitHub Actions. The pipeline builds all packages, type-checks, lints, and runs the test suite across Linux, macOS, and Windows. Native addon builds run on each platform to catch ABI mismatches.

If CI fails:

1. Check the failure type — usually a real bug, a flaky test, or a missing native dep
2. Reproduce locally with the same command CI ran
3. Fix and push a new commit (CI re-runs automatically)

Do **not** disable failing tests to make CI green — that's a regression. If a test is genuinely broken, file an issue and either fix it in the same PR or skip it with `it.skip` and a `// TODO(#issue)` comment.
