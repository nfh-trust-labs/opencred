import { describe, it, expect } from "vitest";
import { sha256, sha256Hex } from "../hash.js";

describe("sha256", () => {
  it("should produce correct hash for empty string", () => {
    const hash = sha256("");
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const hex = Buffer.from(hash).toString("hex");
    expect(hex).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  it("should produce correct hash for known test vector", () => {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    const hash = sha256("abc");
    const hex = Buffer.from(hash).toString("hex");
    expect(hex).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });

  it("should accept Uint8Array input", () => {
    const input = new Uint8Array([0x61, 0x62, 0x63]); // "abc"
    const hash = sha256(input);
    const hex = Buffer.from(hash).toString("hex");
    expect(hex).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });

  it("should return 32 bytes for any input", () => {
    expect(sha256("hello world").length).toBe(32);
    expect(sha256("").length).toBe(32);
    expect(sha256("a".repeat(10000)).length).toBe(32);
  });
});

describe("sha256Hex", () => {
  it("should return hex string for empty input", () => {
    expect(sha256Hex("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  it("should return lowercase hex", () => {
    const hex = sha256Hex("test");
    expect(hex).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should produce consistent output", () => {
    expect(sha256Hex("deterministic")).toBe(sha256Hex("deterministic"));
  });

  it("should produce different output for different inputs", () => {
    expect(sha256Hex("a")).not.toBe(sha256Hex("b"));
  });
});
