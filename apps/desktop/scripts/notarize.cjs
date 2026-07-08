/**
 * macOS notarisation script -- runs as an electron-builder afterSign hook.
 *
 * This script submits the built .app bundle to Apple's notarisation service
 * so that macOS Gatekeeper recognises it as safe to launch.
 *
 * Required environment variables are documented in the CI release workflow
 * (.github/workflows/desktop-release.yml) and should be configured as
 * GitHub Actions secrets.
 *
 * The script is a no-op when:
 *  - Not building for macOS
 *  - CSC_IDENTITY_AUTO_DISCOVERY is set to "false"
 *  - Any required Apple Developer credential env var is missing
 *
 * Environment variables:
 *  - APPLE_ID: Apple Developer account email
 *  - APPLE_APP_SPECIFIC_PASSWORD (or APPLE_ID_PASSWORD): App-specific password
 *  - APPLE_TEAM_ID: Apple Developer Team ID
 *
 * Usage in electron-builder config (package.json):
 *   "afterSign": "scripts/notarize.cjs"
 */

const { notarize } = require("@electron/notarize");
const path = require("path");

module.exports = async function notarizing(context) {
  const { electronPlatformName, appOutDir } = context;

  // Only notarise macOS builds.
  if (electronPlatformName !== "darwin") {
    console.log("Notarize: skipping -- not macOS.");
    return;
  }

  // Skip when code signing identity auto-discovery is disabled (CI smoke tests).
  if (process.env.CSC_IDENTITY_AUTO_DISCOVERY === "false") {
    console.log("Notarize: skipping -- CSC_IDENTITY_AUTO_DISCOVERY is false.");
    return;
  }

  const appleId = process.env.APPLE_ID;
  // Accept both APPLE_APP_SPECIFIC_PASSWORD (preferred) and APPLE_ID_PASSWORD (legacy).
  const appleIdPassword =
    process.env.APPLE_APP_SPECIFIC_PASSWORD || process.env.APPLE_ID_PASSWORD;
  const appleTeamId = process.env.APPLE_TEAM_ID;

  if (!appleId || !appleIdPassword || !appleTeamId) {
    console.log(
      "Notarize: skipping -- missing one or more required Apple Developer env vars " +
        "(APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD or APPLE_ID_PASSWORD, APPLE_TEAM_ID).",
    );
    return;
  }

  const appName = context.packager.appInfo.productFilename;
  const appPath = path.join(appOutDir, `${appName}.app`);

  console.log(`Notarize: submitting ${appPath} to Apple notarisation service...`);

  await notarize({
    appPath,
    appleId,
    appleIdPassword,
    teamId: appleTeamId,
  });

  console.log("Notarize: complete.");
};
