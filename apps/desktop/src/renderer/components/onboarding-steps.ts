/**
 * Onboarding step model — extracted from OnboardingWizard so the
 * internal-step → visible-step mapping can be unit-tested without importing
 * the React component (and its asset/icon imports).
 *
 * The progress indicator shows five plain-language steps. Internal steps (and,
 * for the self-published sub-flow, its reported phase) map onto these so the
 * bar advances one step at a time on every path — fixing the bug where the
 * did:web path jumped "Your key" → "Publish" because the hosting work was
 * hidden inside the old "Set Up Key" step.
 */

export type Step =
  | "welcome"
  | "choose-anchor"
  | "dsc-source"
  | "dsc-upload"
  | "dsc-hardware"
  | "dsc-os-cert"
  | "profile"
  | "get-dsc-soon"
  | "self-pub-setup"
  | "dedi-setup";

export const DISPLAY_STEPS = ["Welcome", "Identity", "Your key", "Publish", "Done"] as const;

/**
 * Self-pub sub-phases that belong to the "Publish" display step. The self-pub
 * sub-flow (SelfPublishedSetup) reports its phase to the wizard; the
 * key-creation phases stay under "Your key" while the host/verify/complete
 * phases advance to "Publish". did:key's confirm/backup phases stay under
 * "Your key" since did:key has nothing to host.
 */
export const SELFPUB_PUBLISH_PHASES = new Set(["domain", "export", "verify", "complete"]);

/**
 * Map an internal step (and, for the self-pub sub-flow, its reported phase) to
 * one of the five visible {@link DISPLAY_STEPS}.
 */
export function getDisplayStepIndex(step: Step, selfPubPhase: string | null = null): number {
  switch (step) {
    case "welcome":
      return 0;
    case "choose-anchor":
    case "get-dsc-soon":
      return 1;
    case "dsc-source":
    case "dsc-upload":
    case "dsc-hardware":
    case "dsc-os-cert":
      return 2;
    case "self-pub-setup":
      return selfPubPhase && SELFPUB_PUBLISH_PHASES.has(selfPubPhase) ? 3 : 2;
    case "profile":
    case "dedi-setup":
      return 3;
    default:
      return 0;
  }
}
