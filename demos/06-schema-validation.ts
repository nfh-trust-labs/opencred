import { createRegistry, Validator } from "@opencred/schema-engine";
import { header, success, info, warn, json, separator, step, error } from "./helpers.js";

export async function main(): Promise<void> {
  header("Demo 06: Schema Validation");

  // Step 1: Create a registry with built-in schemas
  step(1, "Create schema registry with built-in schemas");
  const registry = createRegistry();
  const schemas = registry.listSchemas();
  info(`Registered schemas: ${schemas.join(", ")}`);
  success(`${schemas.length} schemas loaded`);

  separator();

  // Step 2: Create a validator
  step(2, "Create a Validator instance");
  const validator = new Validator(registry);
  success("Validator created with AJV engine");

  separator();

  // Step 3: Validate a correct education credential subject
  step(3, "Validate a valid education credential subject");
  const validEducation = {
    name: "Jane Doe",
    degree: "Bachelor of Science",
    institution: "Example University",
    dateConferred: "2026-06-15",
  };
  const validResult = validator.validateCredentialSubject("education", validEducation);
  json("Valid education data", validEducation);
  json("Validation result", validResult);
  if (validResult.valid) {
    success("Education credential subject is valid");
  }

  separator();

  // Step 4: Validate an invalid education credential subject (missing required fields)
  step(4, "Validate an invalid education credential subject");
  const invalidEducation = {
    name: "Jane Doe",
    // missing: degree, institution, dateConferred
  };
  const invalidResult = validator.validateCredentialSubject("education", invalidEducation);
  json("Invalid education data", invalidEducation);
  json("Validation result", invalidResult);
  if (!invalidResult.valid) {
    warn("Correctly rejected — missing required fields:");
    for (const err of invalidResult.errors) {
      info(`  Field "${err.field}": ${err.message}`);
    }
  }

  separator();

  // Step 5: Validate an employment credential subject
  step(5, "Validate an employment credential subject");
  const validEmployment = {
    name: "John Smith",
    employer: "Example Corp",
    position: "Software Engineer",
    startDate: "2026-03-01",
  };
  const employmentResult = validator.validateCredentialSubject("employment", validEmployment);
  json("Employment data", validEmployment);
  if (employmentResult.valid) {
    success("Employment credential subject is valid");
  }

  separator();

  // Step 6: Validate with bad date format
  step(6, "Validate employment with bad date format");
  const badDateEmployment = {
    name: "John Smith",
    employer: "Example Corp",
    position: "Software Engineer",
    startDate: "not-a-date",
  };
  const badDateResult = validator.validateCredentialSubject("employment", badDateEmployment);
  json("Validation result", badDateResult);
  if (!badDateResult.valid) {
    warn("Correctly rejected — invalid date format:");
    for (const err of badDateResult.errors) {
      info(`  Field "${err.field}": ${err.message}`);
    }
  }

  separator();

  // Step 7: Demonstrate validateOrThrow
  step(7, "Demonstrate validateOrThrow (throws on invalid data)");
  try {
    validator.validateOrThrow("education", { name: "Incomplete" });
    error("Should have thrown!");
  } catch (e) {
    success(`validateOrThrow correctly threw: ${(e as Error).message}`);
  }

  separator();
  success("Demo 06 complete");
}

const isDirectRun = !process.argv[1]?.includes("run-all");
if (isDirectRun) main().catch(console.error);
