import { Hono } from "hono";
import { NotImplementedError } from "@opencred/shared";

export function createSchemaStubRoutes() {
  const schemas = new Hono();
  schemas.get("/", () => { throw new NotImplementedError("Schema listing is not yet implemented"); });
  schemas.get("/:id", () => { throw new NotImplementedError("Schema retrieval is not yet implemented"); });
  schemas.post("/", () => { throw new NotImplementedError("Custom schema registration is not yet implemented"); });
  return schemas;
}

export function createDelegationStubRoutes() {
  const delegations = new Hono();
  delegations.get("/", () => { throw new NotImplementedError("Delegation listing is not yet implemented"); });
  delegations.post("/", () => { throw new NotImplementedError("Delegation creation is not yet implemented"); });
  delegations.get("/:id", () => { throw new NotImplementedError("Delegation retrieval is not yet implemented"); });
  delegations.delete("/:id", () => { throw new NotImplementedError("Delegation revocation is not yet implemented"); });
  return delegations;
}

export function createRevocationStatusStubRoutes() {
  const revocationStatus = new Hono();
  revocationStatus.get("/:hash", () => { throw new NotImplementedError("Revocation status lookup is not yet implemented"); });
  return revocationStatus;
}
