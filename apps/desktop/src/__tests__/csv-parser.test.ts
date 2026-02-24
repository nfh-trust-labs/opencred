/**
 * Tests for the CSV parser.
 *
 * Covers: delimiter detection, CSV parsing, column mapping, schema validation,
 * and edge cases (empty rows, quoted fields, various delimiters).
 */

import { describe, it, expect } from "vitest";
import {
  detectDelimiter,
  parseRawCsv,
  parseCsv,
} from "../batch/csv-parser";

// ---------------------------------------------------------------------------
// Delimiter detection
// ---------------------------------------------------------------------------

describe("detectDelimiter", () => {
  it("should detect comma as the delimiter", () => {
    const csv = "name,degree,institution\nJane,BS,MIT\nJohn,MS,Stanford";
    expect(detectDelimiter(csv)).toBe(",");
  });

  it("should detect semicolon as the delimiter", () => {
    const csv = "name;degree;institution\nJane;BS;MIT\nJohn;MS;Stanford";
    expect(detectDelimiter(csv)).toBe(";");
  });

  it("should detect tab as the delimiter", () => {
    const csv = "name\tdegree\tinstitution\nJane\tBS\tMIT\nJohn\tMS\tStanford";
    expect(detectDelimiter(csv)).toBe("\t");
  });

  it("should default to comma for empty input", () => {
    expect(detectDelimiter("")).toBe(",");
  });

  it("should handle single-line input", () => {
    expect(detectDelimiter("a,b,c")).toBe(",");
  });
});

// ---------------------------------------------------------------------------
// Raw CSV parsing
// ---------------------------------------------------------------------------

describe("parseRawCsv", () => {
  it("should parse basic comma-delimited CSV", () => {
    const csv = "name,degree,institution\nJane,BS,MIT\nJohn,MS,Stanford";
    const result = parseRawCsv(csv, ",");
    expect(result.headers).toEqual(["name", "degree", "institution"]);
    expect(result.rows).toHaveLength(2);
    expect(result.rows[0]).toEqual(["Jane", "BS", "MIT"]);
    expect(result.rows[1]).toEqual(["John", "MS", "Stanford"]);
  });

  it("should handle quoted fields with commas inside", () => {
    const csv = 'name,degree,institution\n"Doe, Jane",BS,"MIT, Cambridge"';
    const result = parseRawCsv(csv, ",");
    expect(result.rows[0][0]).toBe("Doe, Jane");
    expect(result.rows[0][2]).toBe("MIT, Cambridge");
  });

  it("should handle escaped quotes (double-double-quotes)", () => {
    const csv = 'name,title\n"Jane ""JD"" Doe","Dr."';
    const result = parseRawCsv(csv, ",");
    expect(result.rows[0][0]).toBe('Jane "JD" Doe');
  });

  it("should handle empty lines", () => {
    const csv = "name,degree\nJane,BS\n\nJohn,MS\n";
    const result = parseRawCsv(csv, ",");
    expect(result.rows).toHaveLength(2);
  });

  it("should handle CRLF line endings", () => {
    const csv = "name,degree\r\nJane,BS\r\nJohn,MS";
    const result = parseRawCsv(csv, ",");
    expect(result.rows).toHaveLength(2);
  });

  it("should trim values when trim is true", () => {
    const csv = "name , degree , institution\n Jane , BS , MIT ";
    const result = parseRawCsv(csv, ",", true);
    expect(result.headers).toEqual(["name", "degree", "institution"]);
    expect(result.rows[0]).toEqual(["Jane", "BS", "MIT"]);
  });

  it("should not trim values when trim is false", () => {
    const csv = "name , degree\n Jane , BS ";
    const result = parseRawCsv(csv, ",", false);
    expect(result.headers).toEqual(["name ", " degree"]);
    expect(result.rows[0]).toEqual([" Jane ", " BS "]);
  });

  it("should return empty headers and rows for empty input", () => {
    const result = parseRawCsv("", ",");
    expect(result.headers).toEqual([]);
    expect(result.rows).toEqual([]);
  });

  it("should handle semicolon delimiter", () => {
    const csv = "name;degree;institution\nJane;BS;MIT";
    const result = parseRawCsv(csv, ";");
    expect(result.headers).toEqual(["name", "degree", "institution"]);
    expect(result.rows[0]).toEqual(["Jane", "BS", "MIT"]);
  });

  it("should handle tab delimiter", () => {
    const csv = "name\tdegree\tinstitution\nJane\tBS\tMIT";
    const result = parseRawCsv(csv, "\t");
    expect(result.headers).toEqual(["name", "degree", "institution"]);
    expect(result.rows[0]).toEqual(["Jane", "BS", "MIT"]);
  });
});

// ---------------------------------------------------------------------------
// Full CSV parsing with schema validation
// ---------------------------------------------------------------------------

describe("parseCsv", () => {
  const validEducationCsv = [
    "name,degree,institution,dateConferred",
    "Jane Doe,Bachelor of Science,MIT,2025-06-15",
    "John Smith,Master of Arts,Stanford,2025-06-20",
    "Alice Johnson,PhD,Harvard,2025-07-01",
    "Bob Williams,Bachelor of Arts,Yale,2025-08-15",
    "Carol Davis,Master of Science,Princeton,2025-09-01",
  ].join("\n");

  it("should parse valid CSV and validate all rows as valid", () => {
    const result = parseCsv(validEducationCsv, { schemaId: "education" });

    expect(result.headers).toEqual(["name", "degree", "institution", "dateConferred"]);
    expect(result.totalCount).toBe(5);
    expect(result.validCount).toBe(5);
    expect(result.invalidCount).toBe(0);
    expect(result.delimiter).toBe(",");

    for (const row of result.rows) {
      expect(row.valid).toBe(true);
      expect(row.errors).toHaveLength(0);
    }
  });

  it("should detect and report invalid rows", () => {
    const csvWithInvalid = [
      "name,degree,institution,dateConferred",
      "Jane Doe,Bachelor of Science,MIT,2025-06-15",
      "John Smith,,,", // Missing required fields
      "Alice Johnson,PhD,Harvard,2025-07-01",
    ].join("\n");

    const result = parseCsv(csvWithInvalid, { schemaId: "education" });

    expect(result.totalCount).toBe(3);
    expect(result.validCount).toBe(2);
    expect(result.invalidCount).toBe(1);

    // Row 0 and 2 should be valid
    expect(result.rows[0].valid).toBe(true);
    expect(result.rows[2].valid).toBe(true);

    // Row 1 should be invalid
    expect(result.rows[1].valid).toBe(false);
    expect(result.rows[1].errors.length).toBeGreaterThan(0);
  });

  it("should apply column mapping correctly", () => {
    const csv = [
      "Full Name,Qualification,School,Date",
      "Jane Doe,Bachelor of Science,MIT,2025-06-15",
    ].join("\n");

    const result = parseCsv(csv, {
      schemaId: "education",
      columnMapping: {
        "Full Name": "name",
        "Qualification": "degree",
        "School": "institution",
        "Date": "dateConferred",
      },
    });

    expect(result.validCount).toBe(1);
    expect(result.rows[0].valid).toBe(true);
    expect(result.rows[0].mappedSubject).toEqual({
      name: "Jane Doe",
      degree: "Bachelor of Science",
      institution: "MIT",
      dateConferred: "2025-06-15",
    });
  });

  it("should use forced delimiter", () => {
    // This CSV has both commas and semicolons, but we force semicolon
    const csv = "name;degree;institution;dateConferred\nJane Doe;Bachelor of Science;MIT;2025-06-15";

    const result = parseCsv(csv, {
      schemaId: "education",
      delimiter: ";",
    });

    expect(result.delimiter).toBe(";");
    expect(result.validCount).toBe(1);
  });

  it("should handle CSV with more columns than schema fields", () => {
    const csv = [
      "name,degree,institution,dateConferred,extraField",
      "Jane Doe,Bachelor of Science,MIT,2025-06-15,ignored",
    ].join("\n");

    const result = parseCsv(csv, { schemaId: "education" });

    // The extra column should not cause validation to fail
    expect(result.validCount).toBe(1);
    expect(result.rows[0].valid).toBe(true);
  });

  it("should handle employment schema", () => {
    const csv = [
      "name,employer,position,startDate",
      "John Smith,ACME Corp,Engineer,2024-01-15",
    ].join("\n");

    const result = parseCsv(csv, { schemaId: "employment" });
    expect(result.validCount).toBe(1);
    expect(result.rows[0].valid).toBe(true);
  });

  it("should handle identity schema", () => {
    const csv = [
      "name,dateOfBirth,nationality,documentNumber",
      "Alice Johnson,1990-05-20,US,AB123456",
    ].join("\n");

    const result = parseCsv(csv, { schemaId: "identity" });
    expect(result.validCount).toBe(1);
    expect(result.rows[0].valid).toBe(true);
  });

  it("should handle empty CSV", () => {
    const result = parseCsv("", { schemaId: "education" });
    expect(result.totalCount).toBe(0);
    expect(result.headers).toEqual([]);
    expect(result.rows).toEqual([]);
  });

  it("should handle CSV with only headers", () => {
    const result = parseCsv("name,degree,institution,dateConferred", {
      schemaId: "education",
    });
    expect(result.totalCount).toBe(0);
    expect(result.headers).toEqual(["name", "degree", "institution", "dateConferred"]);
  });

  it("should preserve row indices", () => {
    const csv = [
      "name,degree,institution,dateConferred",
      "Jane Doe,BS,MIT,2025-06-15",
      "John Smith,MS,Stanford,2025-06-20",
      "Alice Johnson,PhD,Harvard,2025-07-01",
    ].join("\n");

    const result = parseCsv(csv, { schemaId: "education" });

    expect(result.rows[0].rowIndex).toBe(0);
    expect(result.rows[1].rowIndex).toBe(1);
    expect(result.rows[2].rowIndex).toBe(2);
  });
});
