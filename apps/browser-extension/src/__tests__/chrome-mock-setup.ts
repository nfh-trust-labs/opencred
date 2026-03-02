/**
 * Vitest setup file that provides a minimal chrome.* mock global.
 *
 * This runs before each test file, ensuring the `chrome` global exists
 * when browser extension modules are imported.
 */

import { vi } from "vitest";

type MessageCallback = (message: Record<string, unknown>) => void;
type DisconnectCallback = () => void;

const mockPort = {
  postMessage: vi.fn(),
  onMessage: {
    addListener: vi.fn((_cb: MessageCallback) => {}),
  },
  onDisconnect: {
    addListener: vi.fn((_cb: DisconnectCallback) => {}),
  },
};

/** Test origin that is pre-loaded into dynamic origins. */
export const TEST_ORIGIN = "https://app.test.opencred.example.com";

const chromeMock = {
  runtime: {
    connectNative: vi.fn(() => mockPort),
    sendMessage: vi.fn(),
    onMessage: {
      addListener: vi.fn(),
    },
    lastError: null,
  },
  storage: {
    local: {
      get: vi.fn((_keys: string[], cb: (result: Record<string, unknown>) => void) => {
        // Pre-load a test origin so the background module's dynamicOrigins includes it
        cb({ allowedOrigins: [TEST_ORIGIN] });
      }),
    },
  },
};

(globalThis as Record<string, unknown>)["chrome"] = chromeMock;

// Export for tests to access and customize
export { chromeMock, mockPort };
