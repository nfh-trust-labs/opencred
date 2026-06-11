/**
 * Discriminated-union Result envelope for IPC and HTTP responses.
 *
 * Motivation (HIGH-18 in the 2026-04-20 review): every `*Response`
 * interface in `apps/desktop/src/shared/ipc-types.ts` currently uses
 * the shape `{ success: boolean; ...optional success fields; error? }`.
 * Because every success field is optional, a renderer that checks
 * `if (res.success)` still has to non-null-assert every field it
 * reads — the bang is load-bearing and crashes at runtime when a
 * future refactor forgets to populate one of them.
 *
 * `Result<T, E>` replaces that pattern with a proper tagged union.
 * After `if (res.ok)` TypeScript narrows the type to the success
 * variant with every field required; after `if (!res.ok)` it narrows
 * to the failure variant with the error fields required. No bang.
 *
 * Migration strategy:
 *   1. Start using `Result<TSuccess, TError>` for new handlers.
 *   2. For existing handlers, introduce a parallel `*ResultResponse`
 *      type alongside the legacy `*Response`, and emit both shapes
 *      for one release (dual-emit) while callers migrate.
 *   3. Drop the legacy `*Response` once every caller has migrated.
 *
 * The IPC boundary types live in `apps/desktop/src/shared/ipc-types.ts`;
 * the HTTP response types live in `apps/server/src/routes/*.ts`. Both
 * can import this helper.
 */

export type Ok<T> = { ok: true } & T;

export type Err<E> = { ok: false } & E;

/**
 * A discriminated-union result of a success payload `T` or a failure
 * payload `E`. Both `T` and `E` are flattened into the envelope (no
 * nested `data` / `error` field) so the shape matches the existing
 * `{ success: true, ... }` / `{ success: false, error: ... }` style
 * callers are already familiar with.
 *
 * Example:
 *   type BuildAndSignResult = Result<
 *     { signedCredential: string; proofFormat: UiProofFormat },
 *     { errorCode: OpenCredErrorCodeValue; errorField?: string; message: string }
 *   >;
 */
export type Result<T, E> = Ok<T> | Err<E>;

/**
 * Short-form constructors so handlers can return a result without
 * spelling out the object shape on every line.
 */
export const ok = <T extends object>(value: T): Ok<T> => ({ ok: true, ...value });

export const err = <E extends object>(value: E): Err<E> => ({ ok: false, ...value });

/**
 * Narrowing guard. Useful in callers that receive the wire payload
 * as `unknown` and need to dispatch.
 */
export function isOk<T>(r: { ok: boolean } & T): r is { ok: true } & T {
  return r.ok === true;
}
