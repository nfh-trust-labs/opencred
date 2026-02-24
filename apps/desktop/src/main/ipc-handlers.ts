/**
 * IPC handler registration for the Electron main process.
 *
 * Each handler corresponds to an IPC channel defined in ../shared/ipc-channels.ts.
 * The preload script (preload.ts) exposes these channels to the renderer via
 * contextBridge so that the renderer never has direct access to Node.js APIs.
 *
 * SECURITY INVARIANTS:
 *  - Private keys are NEVER sent to the renderer. Only key metadata (id,
 *    fingerprint, algorithm) is returned over IPC.
 *  - Key material is NEVER logged. Use key ID / fingerprint in diagnostics.
 *  - All crypto operations happen in the main process.
 */

import { ipcMain, dialog, type IpcMainInvokeEvent } from "electron";
import * as fs from "node:fs/promises";
import * as crypto from "node:crypto";
import { IPC_CHANNELS } from "../shared/ipc-channels.js";
import type {
  KeyImportRequest,
  KeyImportResponse,
  KeyListResponse,
  KeyMetadata,
  SignCredentialRequest,
  SignCredentialResponse,
  VerifyCredentialRequest,
  VerifyCredentialResponse,
  FileOpenRequest,
  FileOpenResponse,
  FileSaveRequest,
  FileSaveResponse,
  ConfigGetRequest,
  ConfigSetRequest,
} from "../shared/ipc-types.js";
import { getStore } from "./store.js";

// ---------------------------------------------------------------------------
// In-memory key registry (metadata only — keys stay on disk)
// ---------------------------------------------------------------------------

const importedKeys = new Map<string, KeyMetadata>();

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/**
 * KEY_IMPORT — import a key file from disk.
 *
 * The handler reads the file, computes a fingerprint of the public component,
 * stores metadata in memory, and returns the metadata to the renderer.
 * The private key content is NEVER returned or logged.
 */
async function handleKeyImport(
  _event: IpcMainInvokeEvent,
  request: KeyImportRequest,
): Promise<KeyImportResponse> {
  try {
    const content = await fs.readFile(request.filePath, "utf-8");
    const parsed: unknown = JSON.parse(content);

    if (!parsed || typeof parsed !== "object" || !("kty" in parsed)) {
      return { success: false, error: "Invalid key format: expected a JWK object." };
    }

    // Compute a fingerprint from the *public* components only — never include "d".
    const jwk = parsed as Record<string, unknown>;
    const publicComponents = JSON.stringify({
      kty: jwk["kty"],
      crv: jwk["crv"],
      x: jwk["x"],
      y: jwk["y"],
    });
    const fingerprint = crypto.createHash("sha256").update(publicComponents).digest("hex");

    const id = crypto.randomBytes(16).toString("hex");
    const meta: KeyMetadata = {
      id,
      fingerprint,
      algorithm: `${String(jwk["kty"])} ${String(jwk["crv"] ?? "")}`.trim(),
      importedAt: new Date().toISOString(),
    };

    importedKeys.set(id, meta);

    return { success: true, key: meta };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to import key.";
    return { success: false, error: message };
  }
}

/** KEY_LIST — return metadata for all imported keys. */
async function handleKeyList(): Promise<KeyListResponse> {
  return { keys: Array.from(importedKeys.values()) };
}

/**
 * SIGN_CREDENTIAL — sign an unsigned VC with the specified key.
 *
 * NOTE: This is a scaffold / placeholder. Actual signing logic will be
 * implemented in issue #37 (Desktop: software key signing). For now it
 * returns a stub response to validate the IPC round-trip.
 */
async function handleSignCredential(
  _event: IpcMainInvokeEvent,
  request: SignCredentialRequest,
): Promise<SignCredentialResponse> {
  if (!importedKeys.has(request.keyId)) {
    return { success: false, error: `Key not found: ${request.keyId}` };
  }

  // Placeholder — real implementation in #37.
  return {
    success: false,
    error: "Signing not yet implemented. See issue #37.",
  };
}

/**
 * VERIFY_CREDENTIAL — verify a signed VC.
 *
 * NOTE: Placeholder — real verification will use @opencred/verification.
 */
async function handleVerifyCredential(
  _event: IpcMainInvokeEvent,
  request: VerifyCredentialRequest,
): Promise<VerifyCredentialResponse> {
  try {
    // Validate that the input is at least valid JSON.
    JSON.parse(request.credential);

    // Placeholder — real implementation in a follow-up issue.
    return {
      success: true,
      valid: false,
      message: "Verification not yet implemented. See follow-up issues.",
    };
  } catch {
    return { success: false, error: "Invalid JSON input." };
  }
}

/** FILE_OPEN — show a native open-file dialog and return the file contents. */
async function handleFileOpen(
  _event: IpcMainInvokeEvent,
  request: FileOpenRequest,
): Promise<FileOpenResponse> {
  const result = await dialog.showOpenDialog({
    title: request.title ?? "Open File",
    filters: request.filters ?? [{ name: "All Files", extensions: ["*"] }],
    properties: ["openFile"],
  });

  if (result.canceled || result.filePaths.length === 0) {
    return { content: null, filePath: null };
  }

  const filePath = result.filePaths[0];
  const content = await fs.readFile(filePath, "utf-8");
  return { content, filePath };
}

/** FILE_SAVE — show a native save-file dialog and write contents. */
async function handleFileSave(
  _event: IpcMainInvokeEvent,
  request: FileSaveRequest,
): Promise<FileSaveResponse> {
  const result = await dialog.showSaveDialog({
    defaultPath: request.defaultName,
    filters: request.filters ?? [{ name: "JSON", extensions: ["json"] }],
  });

  if (result.canceled || !result.filePath) {
    return { filePath: null };
  }

  await fs.writeFile(result.filePath, request.content, "utf-8");
  return { filePath: result.filePath };
}

/** GET_OFFLINE_STATUS — return whether the machine appears to be offline. */
async function handleGetOfflineStatus(): Promise<boolean> {
  // In Electron, net.online is the most reliable cross-platform check.
  // However, in the main process we can use a simple navigator-free heuristic.
  // For now, we use a DNS lookup as a connectivity probe.
  try {
    const dns = await import("node:dns/promises");
    await dns.lookup("dns.google");
    return false; // online
  } catch {
    return true; // offline
  }
}

/** GET_CONFIG — read a value from electron-store. */
async function handleGetConfig(
  _event: IpcMainInvokeEvent,
  request: ConfigGetRequest,
): Promise<unknown> {
  const store = getStore();
  return store.get(request.key as keyof typeof store.store);
}

/** SET_CONFIG — write a value to electron-store. */
async function handleSetConfig(
  _event: IpcMainInvokeEvent,
  request: ConfigSetRequest,
): Promise<void> {
  const store = getStore();
  store.set(request.key as keyof typeof store.store, request.value);
}

// ---------------------------------------------------------------------------
// Registration / cleanup
// ---------------------------------------------------------------------------

/**
 * Register all IPC handlers. Call once during app initialisation.
 */
export function registerIpcHandlers(): void {
  ipcMain.handle(IPC_CHANNELS.KEY_IMPORT, handleKeyImport);
  ipcMain.handle(IPC_CHANNELS.KEY_LIST, handleKeyList);
  ipcMain.handle(IPC_CHANNELS.SIGN_CREDENTIAL, handleSignCredential);
  ipcMain.handle(IPC_CHANNELS.VERIFY_CREDENTIAL, handleVerifyCredential);
  ipcMain.handle(IPC_CHANNELS.FILE_OPEN, handleFileOpen);
  ipcMain.handle(IPC_CHANNELS.FILE_SAVE, handleFileSave);
  ipcMain.handle(IPC_CHANNELS.GET_OFFLINE_STATUS, handleGetOfflineStatus);
  ipcMain.handle(IPC_CHANNELS.GET_CONFIG, handleGetConfig);
  ipcMain.handle(IPC_CHANNELS.SET_CONFIG, handleSetConfig);
}

/**
 * Remove all IPC handlers. Call during app shutdown.
 */
export function cleanupIpcHandlers(): void {
  for (const channel of Object.values(IPC_CHANNELS)) {
    ipcMain.removeHandler(channel);
  }
}
