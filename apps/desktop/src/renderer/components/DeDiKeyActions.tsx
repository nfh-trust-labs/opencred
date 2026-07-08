/**
 * DeDiKeyActions — minimal per-key Revoke / Rotate affordance.
 *
 * Surfaces the already-landed `dediSetKeyStatus` IPC to the user. The
 * verification method is derived the same way the main-process handler
 * derives it when publishing:
 *   - did:web issuers reference the active key by its sequential index
 *     (`<did>#key-<n>`, default `#key-0`);
 *   - any other DID method uses the signer's own key id.
 *
 * Revoke is destructive — flipping a key to `revoked` makes verifiers reject
 * EVERY credential that key ever signed — so it is gated behind a confirm
 * step. Rotate (mark a key superseded) leaves already-signed credentials
 * valid and needs no confirmation.
 *
 * No key material crosses this boundary: the renderer only ever passes the
 * public verification method string.
 */

import { useState } from "react";
import { Button } from "./ui/Button";

interface DeDiKeyActionsProps {
  /** The issuer DID (did:web:... or did:key:...). */
  did: string;
  /** The local signer key id (used as the verification method for non-did:web). */
  signerKeyId: string;
  /** The active key's sequential index (did:web only). Defaults to 0. */
  keyIndex?: number;
}

type Pending = "rotate" | "revoke" | null;

export function DeDiKeyActions({ did, signerKeyId, keyIndex = 0 }: DeDiKeyActionsProps) {
  const [pending, setPending] = useState<Pending>(null);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [result, setResult] = useState<{ type: "success" | "error"; message: string } | null>(null);

  // did:web issuers reference the active key by its sequential index
  // (`#key-<n>`); other methods use the signer key id directly. Mirrors the
  // main-process publish handler.
  const vm = did.startsWith("did:web:") ? `${did}#key-${keyIndex}` : signerKeyId;

  async function applyStatus(status: "rotated" | "revoked") {
    setResult(null);
    setPending(status === "revoked" ? "revoke" : "rotate");
    try {
      const response = await window.opencred.dediSetKeyStatus({
        verificationMethod: vm,
        status,
        // On revoke, ask the main process to regenerate the DeDi-hosted did.json
        // so the revoked key drops out of the verification relationships while
        // staying resolvable. Ignored for `rotated` and for non-did:web issuers.
        did,
        hostDidDocument: status === "revoked",
      });
      if (!response.success) {
        setResult({ type: "error", message: response.error ?? "Failed to update key status." });
      } else if (response.statusChange) {
        const { changed, status: applied } = response.statusChange;
        setResult({
          type: "success",
          message: changed
            ? `Key marked ${applied}.`
            : `Key was already ${applied} (no change applied).`,
        });
      } else {
        setResult({ type: "success", message: "Key status updated." });
      }
    } catch (err) {
      setResult({
        type: "error",
        message: err instanceof Error ? err.message : "Failed to update key status.",
      });
    } finally {
      setPending(null);
      setConfirmRevoke(false);
    }
  }

  const busy = pending !== null;

  return (
    <div className="space-y-2 pt-1">
      <p className="text-xs text-txt-muted">
        Manage this key&apos;s status in DeDi. Rotating marks the key superseded; already-signed
        credentials stay valid. Revoking rejects every credential signed by this key.
      </p>

      {result && (
        <div
          className={`rounded-md px-3 py-2 text-xs ${
            result.type === "success"
              ? "bg-state-success-bg text-state-success border border-state-success-border"
              : "bg-state-danger-bg text-state-danger border border-state-danger-border"
          }`}
        >
          {result.message}
        </div>
      )}

      {confirmRevoke ? (
        <div className="space-y-2">
          <p className="text-xs text-state-danger">
            Revoking is permanent and rejects ALL credentials signed by this key. Continue?
          </p>
          <div className="flex gap-2">
            <Button
              variant="danger"
              size="sm"
              disabled={busy}
              onClick={() => void applyStatus("revoked")}
            >
              {pending === "revoke" ? "Revoking..." : "Confirm revoke"}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() => setConfirmRevoke(false)}
            >
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex gap-2">
          <Button
            variant="secondary"
            size="sm"
            disabled={busy}
            onClick={() => void applyStatus("rotated")}
          >
            {pending === "rotate" ? "Rotating..." : "Rotate key"}
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={busy}
            onClick={() => {
              setResult(null);
              setConfirmRevoke(true);
            }}
          >
            Revoke key
          </Button>
        </div>
      )}
    </div>
  );
}
