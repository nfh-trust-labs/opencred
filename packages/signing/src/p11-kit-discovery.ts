/**
 * p11-kit auto-discovery for Linux systems.
 *
 * Provides a function to locate the p11-kit-proxy.so module by checking
 * well-known distribution-specific paths. This module has no dependency
 * on pkcs11js so it can be imported without native binaries.
 */

import { existsSync } from "node:fs";

/**
 * Well-known paths for the p11-kit-proxy.so module on Linux distributions.
 */
const P11_KIT_PROXY_PATHS = [
  "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-proxy.so", // Debian/Ubuntu (x86_64)
  "/usr/lib/aarch64-linux-gnu/pkcs11/p11-kit-proxy.so", // Debian/Ubuntu (ARM64)
  "/usr/lib64/pkcs11/p11-kit-proxy.so", // RHEL/Fedora/CentOS
  "/usr/lib/pkcs11/p11-kit-proxy.so", // Arch Linux
  "/usr/lib/i386-linux-gnu/pkcs11/p11-kit-proxy.so", // Debian/Ubuntu (i386)
];

/**
 * Auto-discover the p11-kit-proxy.so module path on Linux.
 *
 * Checks well-known distribution-specific paths for the p11-kit proxy
 * module. p11-kit aggregates all PKCS#11 modules installed on the system,
 * making it the standard way to access hardware tokens and smart cards
 * on Linux.
 *
 * @returns The absolute path to p11-kit-proxy.so, or null if not found.
 */
export function autoDiscoverP11KitModule(): string | null {
  for (const path of P11_KIT_PROXY_PATHS) {
    if (existsSync(path)) {
      return path;
    }
  }
  return null;
}
