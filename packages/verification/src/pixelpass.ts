/**
 * PixelPass codec — re-exported from `@opencred/shared`.
 *
 * The codec implementation lives in `@opencred/shared` so the format
 * detector (`detectCredentialInputFormat`) and the verification pipeline
 * can both call into it without a circular dependency. This module exists
 * only to keep the public import path `@opencred/verification` →
 * `decodePixelPass` working for existing consumers.
 */

export { decodePixelPass } from "@opencred/shared";
