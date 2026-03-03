/**
 * Tests for the native host installer/uninstaller.
 *
 * Validates:
 *  - Chrome and Firefox manifest generation
 *  - Platform-specific manifest path resolution
 *  - Install and uninstall logic (with mocked fs)
 *  - Windows registry handling
 *  - Error handling for missing parameters
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Mock fs and child_process to avoid real filesystem writes
// ---------------------------------------------------------------------------

const { mockWriteFileSync, mockMkdirSync, mockUnlinkSync, mockExistsSync, mockExecFileSync } = vi.hoisted(() => ({
  mockWriteFileSync: vi.fn(),
  mockMkdirSync: vi.fn(),
  mockUnlinkSync: vi.fn(),
  mockExistsSync: vi.fn().mockReturnValue(false),
  mockExecFileSync: vi.fn(),
}));

vi.mock("node:fs", () => ({
  writeFileSync: mockWriteFileSync,
  mkdirSync: mockMkdirSync,
  unlinkSync: mockUnlinkSync,
  existsSync: mockExistsSync,
}));

vi.mock("node:child_process", () => ({
  execFileSync: mockExecFileSync,
}));

import {
  generateChromeManifest,
  generateFirefoxManifest,
  HOST_NAME,
} from "../install/manifest.js";
import {
  getManifestDir,
  getManifestPath,
  MANIFEST_FILENAME,
  WINDOWS_REGISTRY_KEYS,
} from "../install/paths.js";
import { installHost } from "../install/install-host.js";
import { uninstallHost } from "../install/uninstall-host.js";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("manifest generation", () => {
  it("should generate Chrome manifest with allowed_origins", () => {
    const manifest = generateChromeManifest("/usr/local/bin/opencred-host", [
      "chrome-extension://abcdef123456/",
    ]);

    expect(manifest.name).toBe(HOST_NAME);
    expect(manifest.path).toBe("/usr/local/bin/opencred-host");
    expect(manifest.type).toBe("stdio");
    expect(manifest.allowed_origins).toEqual(["chrome-extension://abcdef123456/"]);
    expect(manifest).not.toHaveProperty("allowed_extensions");
  });

  it("should generate Firefox manifest with allowed_extensions", () => {
    const manifest = generateFirefoxManifest("/usr/local/bin/opencred-host", [
      "opencred@example.com",
    ]);

    expect(manifest.name).toBe(HOST_NAME);
    expect(manifest.path).toBe("/usr/local/bin/opencred-host");
    expect(manifest.type).toBe("stdio");
    expect(manifest.allowed_extensions).toEqual(["opencred@example.com"]);
    expect(manifest).not.toHaveProperty("allowed_origins");
  });

  it("should use the correct host name", () => {
    expect(HOST_NAME).toBe("com.opencred.signing");
  });
});

describe("manifest paths", () => {
  it("should return macOS Chrome path", () => {
    const dir = getManifestDir("chrome", "darwin");
    expect(dir).toContain("Google/Chrome/NativeMessagingHosts");
  });

  it("should return macOS Firefox path", () => {
    const dir = getManifestDir("firefox", "darwin");
    expect(dir).toContain("Mozilla/NativeMessagingHosts");
  });

  it("should return Linux Chrome path", () => {
    const dir = getManifestDir("chrome", "linux");
    expect(dir).toContain(".config/google-chrome/NativeMessagingHosts");
  });

  it("should return Linux Firefox path", () => {
    const dir = getManifestDir("firefox", "linux");
    expect(dir).toContain(".mozilla/native-messaging-hosts");
  });

  it("should return null for Windows (uses registry)", () => {
    expect(getManifestDir("chrome", "win32")).toBeNull();
    expect(getManifestDir("firefox", "win32")).toBeNull();
  });

  it("should build full manifest path", () => {
    const path = getManifestPath("chrome", "darwin");
    expect(path).toContain(MANIFEST_FILENAME);
    expect(path).toContain("NativeMessagingHosts");
  });

  it("should return null manifest path for Windows", () => {
    expect(getManifestPath("chrome", "win32")).toBeNull();
  });

  it("should have correct Windows registry keys", () => {
    expect(WINDOWS_REGISTRY_KEYS.chrome).toContain("Google\\Chrome");
    expect(WINDOWS_REGISTRY_KEYS.chrome).toContain(HOST_NAME);
    expect(WINDOWS_REGISTRY_KEYS.firefox).toContain("Mozilla");
    expect(WINDOWS_REGISTRY_KEYS.firefox).toContain(HOST_NAME);
  });
});

describe("installHost", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should install Chrome manifest on macOS", () => {
    const results = installHost({
      hostPath: "/usr/local/bin/opencred-host",
      chromeExtensionOrigin: "chrome-extension://test123/",
      browser: "chrome",
      platform: "darwin",
    });

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(results[0].browser).toBe("chrome");
    expect(results[0].path).toContain("NativeMessagingHosts");
    expect(mockMkdirSync).toHaveBeenCalled();
    expect(mockWriteFileSync).toHaveBeenCalled();

    // Verify the manifest content
    const writtenContent = mockWriteFileSync.mock.calls[0][1] as string;
    const manifest = JSON.parse(writtenContent);
    expect(manifest.name).toBe(HOST_NAME);
    expect(manifest.type).toBe("stdio");
    expect(manifest.allowed_origins).toContain("chrome-extension://test123/");
  });

  it("should install Firefox manifest on Linux", () => {
    const results = installHost({
      hostPath: "/usr/local/bin/opencred-host",
      firefoxExtensionId: "opencred@example.com",
      browser: "firefox",
      platform: "linux",
    });

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(results[0].browser).toBe("firefox");
    expect(mockWriteFileSync).toHaveBeenCalled();

    const writtenContent = mockWriteFileSync.mock.calls[0][1] as string;
    const manifest = JSON.parse(writtenContent);
    expect(manifest.allowed_extensions).toContain("opencred@example.com");
  });

  it("should install for both browsers", () => {
    const results = installHost({
      hostPath: "/usr/local/bin/opencred-host",
      chromeExtensionOrigin: "chrome-extension://test123/",
      firefoxExtensionId: "opencred@example.com",
      browser: "both",
      platform: "darwin",
    });

    expect(results).toHaveLength(2);
    expect(results[0].browser).toBe("chrome");
    expect(results[0].success).toBe(true);
    expect(results[1].browser).toBe("firefox");
    expect(results[1].success).toBe(true);
    expect(mockWriteFileSync).toHaveBeenCalledTimes(2);
  });

  it("should fail Chrome install when extension origin is missing", () => {
    const results = installHost({
      hostPath: "/usr/local/bin/opencred-host",
      browser: "chrome",
      platform: "darwin",
    });

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(false);
    expect(results[0].error).toContain("Chrome extension origin");
  });

  it("should fail Firefox install when extension ID is missing", () => {
    const results = installHost({
      hostPath: "/usr/local/bin/opencred-host",
      browser: "firefox",
      platform: "darwin",
    });

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(false);
    expect(results[0].error).toContain("Firefox extension ID");
  });

  it("should handle Windows installation with registry", () => {
    const results = installHost({
      hostPath: "C:\\Program Files\\opencred\\host.exe",
      chromeExtensionOrigin: "chrome-extension://test123/",
      browser: "chrome",
      platform: "win32",
    });

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(results[0].registryKey).toContain("Google\\Chrome");
    expect(mockExecFileSync).toHaveBeenCalledWith(
      "reg",
      expect.arrayContaining(["add"]),
      expect.any(Object),
    );
  });
});

describe("uninstallHost", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should remove Chrome manifest on macOS", () => {
    mockExistsSync.mockReturnValue(true);

    const results = uninstallHost({
      browser: "chrome",
      platform: "darwin",
    });

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(mockUnlinkSync).toHaveBeenCalled();
  });

  it("should succeed even if manifest doesn't exist", () => {
    const enoent = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    mockUnlinkSync.mockImplementation(() => { throw enoent; });

    const results = uninstallHost({
      browser: "chrome",
      platform: "darwin",
    });

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(mockUnlinkSync).toHaveBeenCalled();
  });

  it("should uninstall from both browsers", () => {
    mockExistsSync.mockReturnValue(true);

    const results = uninstallHost({
      browser: "both",
      platform: "linux",
    });

    expect(results).toHaveLength(2);
    expect(results.every((r) => r.success)).toBe(true);
  });

  it("should handle Windows uninstallation", () => {
    mockExistsSync.mockReturnValue(true);

    const results = uninstallHost({
      browser: "chrome",
      platform: "win32",
    });

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(mockExecFileSync).toHaveBeenCalledWith(
      "reg",
      expect.arrayContaining(["delete"]),
      expect.any(Object),
    );
  });
});
