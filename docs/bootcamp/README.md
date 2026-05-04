# OpenCred Bootcamp Guide

A facilitator-led, hands-on path through the OpenCred Docker image. Each
attendee builds the image locally (or runs it on a cloud VM), wires in a
signing key, issues their first verifiable credential, verifies it,
packages it as a printable PDF + QR code, and optionally publishes
revocation hashes and DID documents to a DeDi instance.

The bootcamp targets **the Docker variant** of OpenCred — not the
Desktop app. Same packages underneath, same APIs, but the headless
container is the easier shared distribution surface for a workshop.

## Pages in this section

* **[Local Docker track](local-docker.md)** — the default path. Every
  attendee runs the container on their own laptop. Works on macOS,
  Windows (WSL2 or Docker Desktop), and Linux. ~3-hour run sheet, no
  cloud bill.
* **[GCP VM track](gcp-vm.md)** — for facilitators who want a single
  shared VM with per-attendee containers, IAP-tunnelled SSH, and
  optional Cloud KMS for the signing key. ~3-hour run sheet plus
  ~30 minutes of GCP setup.
* **[Postman collection](postman-collection.json)** — pre-built
  collection of every request the bootcamp hits, with pre-/post-request
  scripts that thread `issuerDid`, `lastCredential`, and
  `lastRevocationHash` between requests. Import into Postman, set the
  `apiKey` collection variable, and you can drive the whole flow
  without leaving the GUI.

## What attendees learn

By the end of either track, every attendee can:

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

## Facilitator notes

If you're delivering the bootcamp:

- The **Run sheet** at the top of each track (§1 in both files) is a
  3-hour timing template. Adjust by trimming the §7 "Stretch" sections
  if you're tight on time — §1–§6 are the load-bearing 90 minutes.
- Pre-flight email content lives in the §1 Pre-flight section of each
  track — copy it to attendees ~24 hours before the session so they
  arrive with Docker installed and a key file ready.
- The Postman collection's `baseUrl` is `http://localhost:3100` for both
  tracks (the GCP track surfaces the VM via SSH port-forward to the
  same port). The `apiKey` variable is the only thing each attendee
  needs to set per-laptop.
- DeDi access (URL + auth) is something you provide as facilitator —
  there is no public DeDi endpoint to point attendees at. If you don't
  have a DeDi instance to share, attendees skip §3a and the §7 DeDi
  stretch sections; everything else still runs.
