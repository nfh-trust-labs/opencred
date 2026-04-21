/**
 * Tests for the `credentialHistory` → `recentTemplates` migration.
 *
 * The migration runs once at store initialisation and deletes every
 * previously-persisted VC payload. Any entry that does not already have
 * a matching `recentTemplates` row (by `schemaId`) is inserted as a
 * summary row. `credentialHistory` is cleared afterwards.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("electron-log", () => {
  const scopedLogger = {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  };
  return {
    default: {
      ...scopedLogger,
      scope: () => scopedLogger,
      transports: {
        file: { maxSize: 0, format: "", getFile: () => ({ path: "/tmp/test.log" }) },
        console: { format: "" },
      },
      hooks: { push: vi.fn() },
      initialize: vi.fn(),
    },
  };
});

// Minimal in-memory stand-in for electron-store — the migration only
// needs `get` and `set` to work.
interface InMemoryStore {
  get: (key: string) => unknown;
  set: (key: string, value: unknown) => void;
}

function makeStore(initial: Record<string, unknown>): InMemoryStore {
  const data = { ...initial };
  return {
    get: (key: string) => data[key],
    set: (key: string, value: unknown) => {
      data[key] = value;
    },
  };
}

const { migrateCredentialHistory } = await import("../main/store");

type StoreForMigration = Parameters<typeof migrateCredentialHistory>[0];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("credentialHistory → recentTemplates migration", () => {
  it("migrates legacy entries and clears credentialHistory", () => {
    const store = makeStore({
      credentialHistory: [
        {
          id: "legacy-1",
          schemaId: "education",
          schemaName: "Education",
          subjectSummary: "Alice — BSc",
          issuedAt: "2026-04-10T12:00:00.000Z",
          credentialJson: '{"type":"secret-that-should-not-be-on-disk"}',
          keyFingerprint: "aa:bb",
        },
        {
          id: "legacy-2",
          schemaId: "employment",
          schemaName: "Employment",
          subjectSummary: "Bob — SWE",
          issuedAt: "2026-04-12T12:00:00.000Z",
          credentialJson: '{"type":"still-secret"}',
          keyFingerprint: "cc:dd",
        },
      ],
      recentTemplates: [],
    });

    migrateCredentialHistory(store as unknown as StoreForMigration);

    expect(store.get("credentialHistory")).toEqual([]);

    const templates = store.get("recentTemplates") as Array<{
      schemaId: string;
      schemaName: string;
      useCount: number;
      lastUsedAt: string;
    }>;
    expect(templates).toHaveLength(2);
    const bySchema = Object.fromEntries(templates.map((t) => [t.schemaId, t]));
    expect(bySchema["education"]).toMatchObject({
      schemaId: "education",
      schemaName: "Education",
      useCount: 1,
      lastUsedAt: "2026-04-10T12:00:00.000Z",
    });
    expect(bySchema["employment"]).toMatchObject({
      schemaId: "employment",
      schemaName: "Employment",
      useCount: 1,
      lastUsedAt: "2026-04-12T12:00:00.000Z",
    });
  });

  it("merges with existing recentTemplates without overwriting", () => {
    const store = makeStore({
      credentialHistory: [
        {
          id: "legacy-1",
          schemaId: "education",
          schemaName: "Education",
          subjectSummary: "Alice — BSc",
          issuedAt: "2026-04-05T12:00:00.000Z",
          credentialJson: "{}",
          keyFingerprint: "aa:bb",
        },
      ],
      recentTemplates: [
        {
          schemaId: "education",
          schemaName: "Education",
          lastUsedAt: "2026-04-01T12:00:00.000Z",
          useCount: 3,
        },
      ],
    });

    migrateCredentialHistory(store as unknown as StoreForMigration);

    const templates = store.get("recentTemplates") as Array<{
      schemaId: string;
      useCount: number;
      lastUsedAt: string;
    }>;
    expect(templates).toHaveLength(1);
    // useCount bumped by one legacy entry; lastUsedAt advanced to the
    // newer timestamp from the legacy entry.
    expect(templates[0]?.useCount).toBe(4);
    expect(templates[0]?.lastUsedAt).toBe("2026-04-05T12:00:00.000Z");
  });

  it("is a no-op when credentialHistory is already empty", () => {
    const store = makeStore({
      credentialHistory: [],
      recentTemplates: [{ schemaId: "x", schemaName: "X", lastUsedAt: "z", useCount: 1 }],
    });

    migrateCredentialHistory(store as unknown as StoreForMigration);

    expect(store.get("credentialHistory")).toEqual([]);
    const templates = store.get("recentTemplates") as unknown[];
    expect(templates).toHaveLength(1);
  });

  it("does not write credentialJson into recentTemplates entries", () => {
    const secretJson = '{"private":"MUST_NOT_SURFACE"}';
    const store = makeStore({
      credentialHistory: [
        {
          id: "legacy-1",
          schemaId: "edu",
          schemaName: "Edu",
          subjectSummary: "X",
          issuedAt: "2026-04-10T12:00:00.000Z",
          credentialJson: secretJson,
          keyFingerprint: "x",
        },
      ],
      recentTemplates: [],
    });

    migrateCredentialHistory(store as unknown as StoreForMigration);

    const serialised = JSON.stringify(store.get("recentTemplates"));
    expect(serialised).not.toContain("MUST_NOT_SURFACE");
    expect(serialised).not.toContain("credentialJson");
  });
});
