/**
 * Preload script — bridges the main and renderer processes.
 *
 * This script runs in a sandboxed context with access to the `contextBridge`
 * and `ipcRenderer` APIs from Electron. It exposes a strictly typed API on
 * `window.opencred` that the renderer can call without any direct access to
 * Node.js or Electron internals.
 *
 * SECURITY NOTES:
 *  - Only the methods listed below are exposed. The renderer cannot invoke
 *    arbitrary IPC channels.
 *  - Private key material is NEVER returned to the renderer. Only metadata
 *    (id, fingerprint, algorithm) crosses this boundary.
 *  - contextIsolation: true ensures the renderer's JS context is separate
 *    from this preload context.
 */

import { contextBridge, ipcRenderer } from "electron";
import { IPC_CHANNELS } from "../shared/ipc-channels.js";
import type {
  KeyImportRequest,
  KeyImportResponse,
  KeyListResponse,
  SchemaListResponse,
  SchemaGetRequest,
  SchemaGetResponse,
  SignCredentialRequest,
  SignCredentialResponse,
  BuildAndSignRequest,
  BuildAndSignResponse,
  VerifyCredentialRequest,
  VerifyCredentialResponse,
  PackageCredentialRequest,
  PackageCredentialResponse,
  RevocationQueueRequest,
  RevocationQueueResponse,
  RevocationStatusResponse,
  RevocationPublishResponse,
  BatchStartRequest,
  BatchStartResponse,
  BatchStatusResponse,
  BatchCancelResponse,
  BatchExportRequest,
  BatchExportResponse,
  FileOpenRequest,
  FileOpenResponse,
  FileSaveRequest,
  FileSaveResponse,
  Pkcs11DetectRequest,
  Pkcs11DetectResponse,
  Pkcs11ListSlotsRequest,
  Pkcs11ListSlotsResponse,
  Pkcs11ListKeysRequest,
  Pkcs11ListKeysResponse,
  Pkcs11ConnectRequest,
  Pkcs11ConnectResponse,
  UpdateStatusResponse,
  OsCertListResponse,
  OsCertSignRequest,
  OsCertSignResponse,
  OsCertConnectRequest,
  OsCertConnectResponse,
  OpenCredDesktopAPI,
} from "../shared/ipc-types.js";

const api: OpenCredDesktopAPI = {
  // Key management
  importKey: (request: KeyImportRequest): Promise<KeyImportResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.KEY_IMPORT, request),

  listKeys: (): Promise<KeyListResponse> => ipcRenderer.invoke(IPC_CHANNELS.KEY_LIST),

  // Schema
  listSchemas: (): Promise<SchemaListResponse> => ipcRenderer.invoke(IPC_CHANNELS.SCHEMA_LIST),

  getSchema: (request: SchemaGetRequest): Promise<SchemaGetResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.SCHEMA_GET, request),

  // Signing & verification
  signCredential: (request: SignCredentialRequest): Promise<SignCredentialResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.SIGN_CREDENTIAL, request),

  buildAndSign: (request: BuildAndSignRequest): Promise<BuildAndSignResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.BUILD_AND_SIGN, request),

  verifyCredential: (request: VerifyCredentialRequest): Promise<VerifyCredentialResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.VERIFY_CREDENTIAL, request),

  // Packaging
  packageCredential: (request: PackageCredentialRequest): Promise<PackageCredentialResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.PACKAGE_CREDENTIAL, request),

  // Revocation
  queueRevocation: (request: RevocationQueueRequest): Promise<RevocationQueueResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.REVOCATION_QUEUE, request),

  getRevocationStatus: (): Promise<RevocationStatusResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.REVOCATION_STATUS),

  publishRevocations: (): Promise<RevocationPublishResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.REVOCATION_PUBLISH),

  // Batch issuance
  batchStart: (request: BatchStartRequest): Promise<BatchStartResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.BATCH_START, request),

  batchStatus: (): Promise<BatchStatusResponse> => ipcRenderer.invoke(IPC_CHANNELS.BATCH_STATUS),

  batchCancel: (): Promise<BatchCancelResponse> => ipcRenderer.invoke(IPC_CHANNELS.BATCH_CANCEL),

  batchExport: (request: BatchExportRequest): Promise<BatchExportResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.BATCH_EXPORT, request),

  // File I/O
  openFile: (request: FileOpenRequest): Promise<FileOpenResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.FILE_OPEN, request),

  saveFile: (request: FileSaveRequest): Promise<FileSaveResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.FILE_SAVE, request),

  // Network status
  getOfflineStatus: (): Promise<boolean> => ipcRenderer.invoke(IPC_CHANNELS.GET_OFFLINE_STATUS),

  // PKCS#11 hardware tokens
  pkcs11Detect: (request: Pkcs11DetectRequest): Promise<Pkcs11DetectResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.PKCS11_DETECT, request),

  pkcs11ListSlots: (request: Pkcs11ListSlotsRequest): Promise<Pkcs11ListSlotsResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.PKCS11_LIST_SLOTS, request),

  pkcs11ListKeys: (request: Pkcs11ListKeysRequest): Promise<Pkcs11ListKeysResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.PKCS11_LIST_KEYS, request),

  pkcs11Connect: (request: Pkcs11ConnectRequest): Promise<Pkcs11ConnectResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.PKCS11_CONNECT, request),

  // Auto-update
  updateCheck: (): Promise<UpdateStatusResponse> => ipcRenderer.invoke(IPC_CHANNELS.UPDATE_CHECK),

  updateDownload: (): Promise<UpdateStatusResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.UPDATE_DOWNLOAD),

  updateInstall: (): Promise<void> => ipcRenderer.invoke(IPC_CHANNELS.UPDATE_INSTALL),

  updateGetStatus: (): Promise<UpdateStatusResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.UPDATE_STATUS),

  onUpdateStatus: (callback: (status: UpdateStatusResponse) => void): (() => void) => {
    const handler = (_event: unknown, status: UpdateStatusResponse): void => {
      callback(status);
    };
    ipcRenderer.on(IPC_CHANNELS.UPDATE_STATUS, handler);
    return () => {
      ipcRenderer.removeListener(IPC_CHANNELS.UPDATE_STATUS, handler);
    };
  },

  // OS certificate store
  osCertList: (): Promise<OsCertListResponse> => ipcRenderer.invoke(IPC_CHANNELS.OSCERT_LIST),

  osCertSign: (request: OsCertSignRequest): Promise<OsCertSignResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.OSCERT_SIGN, request),

  osCertConnect: (request: OsCertConnectRequest): Promise<OsCertConnectResponse> =>
    ipcRenderer.invoke(IPC_CHANNELS.OSCERT_CONNECT, request),

  // Config
  getConfig: (key: string): Promise<unknown> =>
    ipcRenderer.invoke(IPC_CHANNELS.GET_CONFIG, { key }),

  setConfig: (key: string, value: unknown): Promise<void> =>
    ipcRenderer.invoke(IPC_CHANNELS.SET_CONFIG, { key, value }),
};

contextBridge.exposeInMainWorld("opencred", api);
