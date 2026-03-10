import { Hono } from "hono";
import { NotImplementedError } from "@opencred/shared";

export function createRevocationStatusStubRoutes() {
  const revocationStatus = new Hono();
  revocationStatus.get("/:hash", () => { throw new NotImplementedError("Revocation status lookup is not yet implemented"); });
  return revocationStatus;
}
