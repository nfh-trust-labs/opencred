import type { VerifiableCredential } from "@opencred/vc-core";

/**
 * A credential as it enters the packager. Two shapes are supported:
 *
 *  - `vc`            — a JSON-LD VerifiableCredential object (Data Integrity
 *                      proof or VC-JWT-with-proof envelope).
 *  - `compact-token` — a compact serialized JWT or SD-JWT-VC string. The
 *                      packager treats the token as opaque payload: it goes
 *                      directly into the QR/PDF/JSON outputs without
 *                      PixelPass compression and without re-parsing.
 *
 * The discriminator is intentional — `string` alone would be ambiguous with
 * a stringified-JSON credential, which is a valid mistake to forbid at the
 * type level.
 */
export type CredentialInput =
  | { kind: "vc"; credential: VerifiableCredential }
  | { kind: "compact-token"; token: string };

/**
 * Subset of VerifiableCredential fields the offline renderers
 * (`generatePdf`, `exportAsJson`) actually read. Used for the synthetic
 * shape produced by `decode-for-display.ts` when packaging a compact
 * token: the decoded JWT/SD-JWT body is not a full JSON-LD VC, but it has
 * enough of the surface for display.
 *
 * NOTE: this is a documentation device for the boundary between the
 * input-side discriminated union and the output-side rendering pipeline.
 * Widening renderer signatures from `VerifiableCredential` to
 * `PartialVerifiableCredential` removes the `as unknown as
 * VerifiableCredential` cast that previously hid this gap.
 */
export interface PartialVerifiableCredential {
  id: string;
  type: string[];
  issuer: VerifiableCredential["issuer"];
  credentialSubject: VerifiableCredential["credentialSubject"];
  validFrom?: string;
  validUntil?: string;
  proof?: VerifiableCredential["proof"];
  "@context"?: VerifiableCredential["@context"];
}
