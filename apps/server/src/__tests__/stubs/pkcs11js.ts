/**
 * Stub for pkcs11js native module — the server doesn't use PKCS#11.
 */

export class PKCS11 {
  load() {
    throw new Error("PKCS#11 stub — not available in server tests");
  }
  C_Initialize() {
    throw new Error("PKCS#11 stub");
  }
  C_Finalize() {}
  C_GetSlotList() {
    return [];
  }
  C_GetTokenInfo() {
    return {};
  }
  C_OpenSession() {
    return 0;
  }
  C_CloseSession() {}
  C_Login() {}
  C_Logout() {}
  C_FindObjectsInit() {}
  C_FindObjects() {
    return [];
  }
  C_FindObjectsFinal() {}
  C_GetAttributeValue() {
    return [];
  }
  C_SignInit() {}
  C_Sign() {
    return Buffer.alloc(0);
  }
}

export default PKCS11;
