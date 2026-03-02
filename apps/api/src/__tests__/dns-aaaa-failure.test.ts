import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { TTLStore } from "@opencred/state";
import { createDomainVerificationRoutes, generateToken, CHALLENGE_TTL_MS, type ChallengeRecord } from "../routes/domain-verification.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

const logger = makeTestLogger();

interface ConfirmResponse { verified: boolean; domain: string; method: string; verifiedAt?: string }
interface ErrorBody { error: { code: string; message: string } }

describe("DNS AAAA failure handling (#140)", () => {
  it("fails HTTP verification when both A and AAAA lookups fail", async () => {
    const challengeStore = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 60_000);
    const token = generateToken();
    const challengeId = "ch_test-aaaa-fail";
    challengeStore.set(challengeId, { id: challengeId, domain: "test.example.com", method: "http-challenge", token, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString(), verified: false }, CHALLENGE_TTL_MS);

    const servFailResolve4 = async () => { const err = new Error("queryA SERVFAIL"); (err as NodeJS.ErrnoException).code = "SERVFAIL"; throw err; };
    const servFailResolve6 = async () => { const err = new Error("queryAAAA SERVFAIL"); (err as NodeJS.ErrnoException).code = "SERVFAIL"; throw err; };

    const app = new Hono();
    app.route("/onboarding", createDomainVerificationRoutes({ challengeStore, dnsResolve4: servFailResolve4, dnsResolve6: servFailResolve6, httpFetch: async () => ({ ok: true, text: async () => token }) }));
    app.onError(errorHandler(logger));

    const res = await app.request("/onboarding/domain-verify/confirm", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ challengeId }) });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("DNS resolution failed");
  });

  it("succeeds when AAAA lookup fails but A lookup returns public IP", async () => {
    const challengeStore = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 60_000);
    const token = generateToken();
    const challengeId = "ch_test-aaaa-fail-a-ok";
    challengeStore.set(challengeId, { id: challengeId, domain: "test.example.com", method: "http-challenge", token, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString(), verified: false }, CHALLENGE_TTL_MS);

    const servFailResolve6 = async () => { const err = new Error("queryAAAA SERVFAIL"); (err as NodeJS.ErrnoException).code = "SERVFAIL"; throw err; };

    const app = new Hono();
    app.route("/onboarding", createDomainVerificationRoutes({ challengeStore, dnsResolve4: async () => ["93.184.216.34"], dnsResolve6: servFailResolve6, httpFetch: async () => ({ ok: true, text: async () => token }) }));
    app.onError(errorHandler(logger));

    const res = await app.request("/onboarding/domain-verify/confirm", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ challengeId }) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as ConfirmResponse;
    expect(body.verified).toBe(true);
  });

  it("fails when AAAA returns private IP and A lookup also fails", async () => {
    const challengeStore = new TTLStore<ChallengeRecord>(CHALLENGE_TTL_MS, 60_000);
    const token = generateToken();
    const challengeId = "ch_test-private-ipv6";
    challengeStore.set(challengeId, { id: challengeId, domain: "test.example.com", method: "http-challenge", token, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString(), verified: false }, CHALLENGE_TTL_MS);

    const noARecords = async () => { const err = new Error("queryA ENODATA"); (err as NodeJS.ErrnoException).code = "ENODATA"; throw err; };

    const app = new Hono();
    app.route("/onboarding", createDomainVerificationRoutes({ challengeStore, dnsResolve4: noARecords, dnsResolve6: async () => ["::1"], httpFetch: async () => ({ ok: true, text: async () => token }) }));
    app.onError(errorHandler(logger));

    const res = await app.request("/onboarding/domain-verify/confirm", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ challengeId }) });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("private or reserved");
  });
});
