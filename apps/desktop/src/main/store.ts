/**
 * Local configuration store backed by electron-store.
 *
 * Persists user preferences such as the last-used key ID, window state,
 * and application settings. Data is stored as an encrypted JSON file in
 * the platform-appropriate user data directory.
 *
 * SECURITY NOTE: Never store private keys, signing buffers, or credential
 * payloads in this store. Only metadata and user preferences are persisted.
 */

import ElectronStore from "electron-store";

export interface StoreSchema {
  /** ID of the last-used signing key (for convenience, not the key itself). */
  lastKeyId: string | undefined;
  /** User-preferred theme. */
  theme: "light" | "dark" | "system";
  /** Whether to start in offline-first mode. */
  offlineMode: boolean;
  /** Custom user preferences — intentionally loosely typed for extensibility. */
  preferences: Record<string, unknown>;
}

const DEFAULTS: StoreSchema = {
  lastKeyId: undefined,
  theme: "system",
  offlineMode: false,
  preferences: {},
};

let store: ElectronStore<StoreSchema> | null = null;

/**
 * Initialise the store. Call once during app startup.
 */
export function initStore(): ElectronStore<StoreSchema> {
  if (!store) {
    store = new ElectronStore<StoreSchema>({
      name: "opencred-config",
      defaults: DEFAULTS,
    });
  }
  return store;
}

/**
 * Get the singleton store instance.
 * @throws if called before {@link initStore}.
 */
export function getStore(): ElectronStore<StoreSchema> {
  if (!store) {
    throw new Error("Store has not been initialised. Call initStore() first.");
  }
  return store;
}
