import { describe, it, expect } from "vitest";
import { DISPLAY_STEPS, getDisplayStepIndex } from "../renderer/components/onboarding-steps";

describe("onboarding step model (#715)", () => {
  it("exposes five plain-language visible steps", () => {
    expect(DISPLAY_STEPS).toEqual(["Welcome", "Identity", "Your key", "Publish", "Done"]);
  });

  it("maps the static steps", () => {
    expect(getDisplayStepIndex("welcome")).toBe(0);
    expect(getDisplayStepIndex("choose-anchor")).toBe(1);
    expect(getDisplayStepIndex("dsc-source")).toBe(2);
    expect(getDisplayStepIndex("dsc-upload")).toBe(2);
    expect(getDisplayStepIndex("dsc-hardware")).toBe(2);
    expect(getDisplayStepIndex("dsc-os-cert")).toBe(2);
    expect(getDisplayStepIndex("profile")).toBe(3);
    expect(getDisplayStepIndex("dedi-setup")).toBe(3);
  });

  describe("self-pub sub-phase mapping", () => {
    it("keeps key-creation phases under 'Your key'", () => {
      for (const phase of ["generate", "choose-method", "did-key-confirm", "did-key-backup"]) {
        expect(getDisplayStepIndex("self-pub-setup", phase)).toBe(2);
      }
    });

    it("advances host/verify/complete phases to 'Publish'", () => {
      for (const phase of ["domain", "export", "verify", "complete"]) {
        expect(getDisplayStepIndex("self-pub-setup", phase)).toBe(3);
      }
    });

    it("defaults to 'Your key' when no phase is reported yet", () => {
      expect(getDisplayStepIndex("self-pub-setup")).toBe(2);
      expect(getDisplayStepIndex("self-pub-setup", null)).toBe(2);
    });
  });

  // Regression for the original bug: the did:web path used to jump "Your key"
  // straight past "Publish" because the hosting work was hidden inside the old
  // "Set Up Key" step. Every path must now advance one step at a time.
  describe("no visible step is skipped on any path", () => {
    function assertNoGap(indices: number[]) {
      const seen = [...new Set(indices)].sort((a, b) => a - b);
      for (let i = 1; i < seen.length; i++) {
        expect(seen[i]! - seen[i - 1]!).toBeLessThanOrEqual(1);
      }
    }

    it("website (did:web on your domain)", () => {
      assertNoGap([
        getDisplayStepIndex("welcome"),
        getDisplayStepIndex("choose-anchor"),
        getDisplayStepIndex("self-pub-setup", "generate"),
        getDisplayStepIndex("self-pub-setup", "domain"),
        getDisplayStepIndex("self-pub-setup", "export"),
        getDisplayStepIndex("self-pub-setup", "verify"),
        getDisplayStepIndex("self-pub-setup", "complete"),
        getDisplayStepIndex("dedi-setup"),
      ]);
    });

    it("public directory (did:web via DeDi namespace)", () => {
      assertNoGap([
        getDisplayStepIndex("welcome"),
        getDisplayStepIndex("choose-anchor"),
        getDisplayStepIndex("self-pub-setup", "generate"),
        getDisplayStepIndex("self-pub-setup", "domain"),
        getDisplayStepIndex("self-pub-setup", "export"),
        getDisplayStepIndex("self-pub-setup", "complete"),
        getDisplayStepIndex("dedi-setup"),
      ]);
    });

    it("just get started (did:key)", () => {
      assertNoGap([
        getDisplayStepIndex("welcome"),
        getDisplayStepIndex("choose-anchor"),
        getDisplayStepIndex("self-pub-setup", "generate"),
        getDisplayStepIndex("self-pub-setup", "did-key-confirm"),
        getDisplayStepIndex("self-pub-setup", "did-key-backup"),
        getDisplayStepIndex("self-pub-setup", "complete"),
        getDisplayStepIndex("dedi-setup"),
      ]);
    });

    it("official certificate (DSC)", () => {
      assertNoGap([
        getDisplayStepIndex("welcome"),
        getDisplayStepIndex("choose-anchor"),
        getDisplayStepIndex("dsc-source"),
        getDisplayStepIndex("dsc-upload"),
        getDisplayStepIndex("profile"),
        getDisplayStepIndex("dedi-setup"),
      ]);
    });
  });

  it("did:web hosting reaches 'Publish' (the regression target)", () => {
    expect(getDisplayStepIndex("self-pub-setup", "export")).toBe(3);
  });
});
