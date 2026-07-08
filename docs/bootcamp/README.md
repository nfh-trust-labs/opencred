# OpenCred Bootcamp Guide

A self-service, hands-on path through the OpenCred Docker image. You'll run the image locally (or on a cloud VM), wire in a signing key, issue your first verifiable credential, verify it, package it as a printable PDF + QR code, and optionally publish revocation hashes and DID documents to a DeDi instance.

The bootcamp targets **the Docker variant** of OpenCred — not the Desktop app. Same packages underneath, same APIs, but the headless container is the easier surface to drive end-to-end from a shell.

## Pages in this section

* **[Local Docker track](local-docker.md)** — the default path. Run the container on your own laptop. Works on macOS, Windows (WSL2 or Docker Desktop), and Linux. ~90 minutes hands-on, no cloud bill.
* **[GCP VM track](gcp-vm.md)** — alternative path on a Google Compute Engine VM with IAP-tunnelled SSH and optional Cloud KMS for the signing key. ~90 minutes hands-on plus ~30 minutes of GCP setup.
* **[Postman collection](postman-collection.json)** — pre-built collection of every request the bootcamp hits, with pre-/post-request scripts that thread `issuerDid`, `lastCredential`, and `lastRevocationHash` between requests. Import into Postman, set the `apiKey` collection variable, and you can drive the whole flow without leaving the GUI.

## What you'll learn

By the end of either track, you'll be able to:

1. Run a hardened OpenCred container locally (read-only rootfs, no caps,
   non-root user).
2. Generate a P-256 signing key and load it into the container.
3. Issue a JSON-LD VC, a vc-jwt VC, an sd-jwt-vc compact token, and a
   credential against an entirely custom JSON Schema they paste at
   request time.
4. Verify each format end-to-end, with a `valid: true` and a
   per-check breakdown.
5. Package any of the above as a printable PDF certificate with an
   embedded scannable QR code, branded with their own colors and
   issuer name.
6. (Stretch) Publish a revocation hash and a DID document to a DeDi
   instance, and resolve them back.

## What this guide doesn't cover

- **Production deployment** — see [Docker Operator Guide](../docker/README.md)
  for `docker compose`, env-var reference, observability, Cloud HSM,
  and the OID4VCI plans.
- **The Desktop app** — see [Desktop User Guide](../desktop/README.md).
- **The internals** — `@opencred/crypto`, `@opencred/vc-core`,
  `@opencred/verification`, etc. live in
  [Developer Guide](../development/README.md).
- **Trust-chain theory** — the bootcamp uses self-issued `did:key` for
  simplicity. For DSC chains, did:web with TLS-anchored trust, and the
  three issuer types, see [Concepts → Trust chains](../concepts/trust-chains.md).

## DeDi access (optional)

The DeDi sections (§3a and the §7 stretch sections in both tracks) require an OpenCred DeDi instance you can write to. There is no public DeDi endpoint to point at — if you don't have one set up, skip those sections; everything else still runs end-to-end.

## Support

For bug reports, feature requests, or questions while working through the bootcamp, [open an issue](https://github.com/nfh-trust-labs/opencred-releases/issues).
