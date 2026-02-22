import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import {
  createCapabilityToken,
  validateCapabilityToken,
  checkScope,
} from "../capability-token.js";
import { ValidationError } from "@opencred/shared";

describe("Capability Tokens", () => {
  const signingKey = randomBytes(32);

  describe("createCapabilityToken + validateCapabilityToken round-trip", () => {
    it("should create and validate a token successfully", async () => {
      const token = await createCapabilityToken({
        subject: "user-123",
        issuer: "opencred",
        expiresInSeconds: 3600,
        scope: ["vc:issue", "vc:read"],
        namespace: "org-1",
        signingKey,
      });

      expect(typeof token).toBe("string");
      expect(token.split(".")).toHaveLength(3);

      const result = await validateCapabilityToken({
        token,
        verificationKey: signingKey,
        issuer: "opencred",
      });

      expect(result.valid).toBe(true);
      expect(result.payload).toBeDefined();
      expect(result.payload!.sub).toBe("user-123");
      expect(result.payload!.iss).toBe("opencred");
      expect(result.payload!.scope).toEqual(["vc:issue", "vc:read"]);
      expect(result.payload!.namespace).toBe("org-1");
      expect(result.payload!.jti).toBeDefined();
      expect(result.payload!.exp).toBeGreaterThan(result.payload!.iat);
    });

    it("should support audience claim", async () => {
      const token = await createCapabilityToken({
        subject: "user-456",
        issuer: "opencred",
        audience: "api-server",
        expiresInSeconds: 3600,
        scope: ["vc:read"],
        namespace: "org-1",
        signingKey,
      });

      const result = await validateCapabilityToken({
        token,
        verificationKey: signingKey,
        audience: "api-server",
      });

      expect(result.valid).toBe(true);
      expect(result.payload!.aud).toBe("api-server");
    });
  });

  describe("expired token rejection", () => {
    it("should reject an expired token", async () => {
      const token = await createCapabilityToken({
        subject: "user-123",
        issuer: "opencred",
        expiresInSeconds: -10,
        scope: ["vc:issue"],
        namespace: "org-1",
        signingKey,
      });

      const result = await validateCapabilityToken({
        token,
        verificationKey: signingKey,
      });

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe("scope checking", () => {
    it("should confirm scope that exists in the token", async () => {
      const token = await createCapabilityToken({
        subject: "user-123",
        issuer: "opencred",
        expiresInSeconds: 3600,
        scope: ["vc:issue", "vc:read", "vc:revoke"],
        namespace: "org-1",
        signingKey,
      });

      const result = await validateCapabilityToken({
        token,
        verificationKey: signingKey,
      });

      expect(result.valid).toBe(true);
      expect(checkScope(result.payload!, "vc:issue")).toBe(true);
      expect(checkScope(result.payload!, "vc:read")).toBe(true);
      expect(checkScope(result.payload!, "vc:revoke")).toBe(true);
    });

    it("should reject scope that does not exist in the token", async () => {
      const token = await createCapabilityToken({
        subject: "user-123",
        issuer: "opencred",
        expiresInSeconds: 3600,
        scope: ["vc:read"],
        namespace: "org-1",
        signingKey,
      });

      const result = await validateCapabilityToken({
        token,
        verificationKey: signingKey,
      });

      expect(result.valid).toBe(true);
      expect(checkScope(result.payload!, "vc:issue")).toBe(false);
      expect(checkScope(result.payload!, "vc:delete")).toBe(false);
    });

    it("should reject empty scope during creation", async () => {
      await expect(
        createCapabilityToken({
          subject: "user-123",
          issuer: "opencred",
          expiresInSeconds: 3600,
          scope: [],
          namespace: "org-1",
          signingKey,
        }),
      ).rejects.toThrow(ValidationError);
    });
  });

  describe("malformed token handling", () => {
    it("should reject a completely invalid token string", async () => {
      const result = await validateCapabilityToken({
        token: "not-a-jwt",
        verificationKey: signingKey,
      });

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should reject a token signed with a different key", async () => {
      const otherKey = randomBytes(32);

      const token = await createCapabilityToken({
        subject: "user-123",
        issuer: "opencred",
        expiresInSeconds: 3600,
        scope: ["vc:read"],
        namespace: "org-1",
        signingKey: otherKey,
      });

      const result = await validateCapabilityToken({
        token,
        verificationKey: signingKey,
      });

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should reject a token with wrong issuer", async () => {
      const token = await createCapabilityToken({
        subject: "user-123",
        issuer: "opencred",
        expiresInSeconds: 3600,
        scope: ["vc:read"],
        namespace: "org-1",
        signingKey,
      });

      const result = await validateCapabilityToken({
        token,
        verificationKey: signingKey,
        issuer: "other-issuer",
      });

      expect(result.valid).toBe(false);
    });
  });

  describe("namespace isolation", () => {
    it("should bind tokens to their namespace", async () => {
      const tokenOrgA = await createCapabilityToken({
        subject: "user-123",
        issuer: "opencred",
        expiresInSeconds: 3600,
        scope: ["vc:issue"],
        namespace: "org-a",
        signingKey,
      });

      const tokenOrgB = await createCapabilityToken({
        subject: "user-123",
        issuer: "opencred",
        expiresInSeconds: 3600,
        scope: ["vc:issue"],
        namespace: "org-b",
        signingKey,
      });

      const resultA = await validateCapabilityToken({
        token: tokenOrgA,
        verificationKey: signingKey,
      });
      const resultB = await validateCapabilityToken({
        token: tokenOrgB,
        verificationKey: signingKey,
      });

      expect(resultA.valid).toBe(true);
      expect(resultB.valid).toBe(true);
      expect(resultA.payload!.namespace).toBe("org-a");
      expect(resultB.payload!.namespace).toBe("org-b");

      // Token for org-a does NOT grant access to org-b
      expect(resultA.payload!.namespace).not.toBe("org-b");
      expect(resultB.payload!.namespace).not.toBe("org-a");
    });

    it("should reject token creation without namespace", async () => {
      await expect(
        createCapabilityToken({
          subject: "user-123",
          issuer: "opencred",
          expiresInSeconds: 3600,
          scope: ["vc:read"],
          namespace: "",
          signingKey,
        }),
      ).rejects.toThrow(ValidationError);
    });
  });

  describe("unique token IDs", () => {
    it("should generate unique jti for each token", async () => {
      const opts = {
        subject: "user-123",
        issuer: "opencred",
        expiresInSeconds: 3600,
        scope: ["vc:read"],
        namespace: "org-1",
        signingKey,
      };

      const token1 = await createCapabilityToken(opts);
      const token2 = await createCapabilityToken(opts);

      const result1 = await validateCapabilityToken({
        token: token1,
        verificationKey: signingKey,
      });
      const result2 = await validateCapabilityToken({
        token: token2,
        verificationKey: signingKey,
      });

      expect(result1.payload!.jti).not.toBe(result2.payload!.jti);
    });
  });
});
