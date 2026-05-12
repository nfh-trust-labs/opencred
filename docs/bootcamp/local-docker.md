# OpenCred Docker Bootcamp

> **Goal**: have the OpenCred Docker image running on your laptop, issue a real signed Verifiable Credential with your own key, and verify it.
>
> **Time**: ~90 minutes hands-on. Add ~30 min if you've never run a Docker image before.
>
> **Prereqs**: comfortable on a Unix shell, have used `curl`, have Docker installed. No prior VC / DID knowledge required.

A few notes before you start:

- **OpenCred is not a hosted service.** You run your own server, generate your own key, and sign in your own container. NFH Trust Labs sees nothing.
- **Use EC P-256 keys, not RSA.** The `data-integrity` proof format is unsupported on RSA — P-256 lets you demo all three proof formats (`vc-jwt`, `data-integrity`, `sd-jwt-vc`) without surprises.
- **Use `functional-identity/v1` as the demo schema.** It's in the built-in registry, required fields are minimal (`name`, `role`, `validFrom`), and produces a satisfying-looking VC.
- **Don't enable `OPENCRED_DEV_MODE_NO_AUTH`.** Generate an API key — it's 15 seconds and keeps the right mental model that the server is a signing oracle. The server refuses to start with this flag if `NODE_ENV=production`.

---

### 1. Pre-flight

| Tool | Why | Check |
|---|---|---|
| Docker 24+ | Build and run the image | `docker --version` |
| Docker Compose v2 (optional) | Stretch goal | `docker compose version` |
| `git` | Clone the repo | `git --version` |
| `curl` | Hit the API from the shell | `curl --version` |
| `openssl` | Generate the signing key | `openssl version` |
| `jq` (optional but useful) | Pretty-print JSON | `jq --version` |
| **Postman** (optional alternative to curl) | A pre-built collection of every request below | <https://www.postman.com/downloads/> |

Storage: ~2 GB free for the image. RAM: 1 GB is fine.

> **Postman or curl — pick whichever you prefer.** Every API call in §5
> onwards is provided in two forms: a copy-pasteable `curl` command in
> this guide, and an equivalent request in
> [`postman-collection.json`](postman-collection.json) (sibling file in
> this directory; download the raw JSON). Pick one and stick with it;
> the requests are identical. If you go with Postman, do **Import →
> drop the file → set the `baseUrl` and `apiKey` collection
> variables**, then jump to §5.

If `docker run hello-world` works, you are ready.

> **Architecture support**: starting with **v1.2.0**, the published image is a
> multi-arch manifest (linux/amd64 + linux/arm64). Docker auto-selects the
> right variant for your CPU — Apple Silicon Macs, AWS Graviton, Raspberry Pi,
> and amd64 cloud VMs all `docker pull` without flags. If you're pulling an
> older tag (`:1.0.x` or `:1.1.x`), those are amd64-only; on arm64 hosts add
> `--platform=linux/amd64` to `docker pull` / `docker run`.

### 2. Get the image

The fastest path is to pull the public prebuilt image:

```bash
docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest

# Tag it locally so the rest of this guide reads naturally
docker tag ghcr.io/nfh-trust-labs/opencred/opencred-server:latest opencred:bootcamp
```

This is a public image — no GHCR auth required. ~150 MB. Skip ahead to §3.

#### 2b. (Optional) Build from source

If you want to inspect the Dockerfile, modify the schema engine, or work
offline, build it yourself instead of pulling:

```bash
git clone https://github.com/nfh-trust-labs/opencred.git
cd opencred
git checkout new-opencred-dev

# Build from the repo root — the Dockerfile path is relative.
docker build -f apps/server/Dockerfile -t opencred:bootcamp .
```

> The source repo is private. If `git clone` returns 404, pull the prebuilt
> image instead — the bootcamp does not depend on you having read access to
> the source.

The build is multi-stage: it installs pnpm, builds every `@opencred/*` workspace
package the server depends on, prunes dev deps, and copies the result into a
`node:20-alpine` runtime stage that runs as the non-root `node` user. Expect
3–8 minutes on a warm cache, longer on first run.

Sanity-check the image is there:

```bash
docker images opencred:bootcamp
```

### 3. Generate a signing key and an API token

These both live on **your** filesystem only. Nothing leaves your laptop.

```bash
mkdir -p ~/opencred-bootcamp/keys
cd ~/opencred-bootcamp

# EC P-256 private key in PKCS#8 PEM — works with all three proof formats.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out keys/issuer-key.pem
chmod 600 keys/issuer-key.pem

# A strong random bearer token.
export OPENCRED_API_KEY="$(openssl rand -base64 32)"
echo "Save this somewhere — you'll paste it into curl: $OPENCRED_API_KEY"
```

> **Security beat to call out**: the server treats `POST /v1/credentials/issue`
> as a signing oracle. Anyone who can reach that endpoint with a valid token
> can mint credentials with your key. So the key file (`0600`) and the token
> (kept out of shell history, env var only) both matter.

#### 3a. (Optional) Set up DeDi for revocation + public-key registry

If you have DeDi access (URL, API key or bearer creds, namespace name), export them now so they're picked up by the §4 `docker run`. **Skip this entire block if you don't have DeDi access** — every other section of the bootcamp works without DeDi, and `/v1/health` will simply report `dediConfigured: false`.

> **Note for zsh users**: zsh doesn't treat `#` as a comment by default
> in interactive shells. If you copy-paste the block below and see
> `unknown file attribute: B` (or similar), run `setopt
> interactive_comments` first, or just delete the `#` lines before
> pasting.

```bash
# Skip this block if you don't have DeDi access.
export OPENCRED_DEDI_BASE_URL="https://your-dedi-instance.example.org"
export OPENCRED_DEDI_AUTH_TYPE="api-key"
export OPENCRED_DEDI_API_KEY="paste-your-token-here"
export OPENCRED_DEDI_NAMESPACE="your-namespace-id"
```

> **What goes in `OPENCRED_DEDI_NAMESPACE`?** Use the namespace ID issued to you by your DeDi operator. The format depends on whether your namespace is verified:
>
> - **Unverified namespace** → looks like `did:web:did.cord.network:xyz` — the DeDi instance's own did:web with your ID appended. This is the default when the operator provisions a new namespace without a domain-ownership challenge.
> - **Verified namespace** → looks like `xyz.org` — your own domain, used directly as the namespace ID after you've proved ownership to the DeDi operator.
>
> Use whichever value the operator gave you. Both work identically with OpenCred; only the DID resolution path that verifiers walk differs.

For **bearer auth** instead of api-key, set `OPENCRED_DEDI_AUTH_TYPE=bearer` and use `OPENCRED_DEDI_EMAIL` + `OPENCRED_DEDI_PASSWORD` instead of `OPENCRED_DEDI_API_KEY`.

The OpenCred container's startup hook calls `ensureRegistries()` on
first boot — your namespace and the four registries inside it
(`vc-revocation-registry`, `public_key_registry`, `schema_registry`,
`context_registry`) get created if missing and reused if they already
exist. No pre-provisioning required.

### 4. Run the container

The command below threads through any DeDi env vars you exported in
§3a. If you skipped §3a, the DeDi block expands to empty and the
container starts in DeDi-disabled mode — both work without edits.

```bash
# Conditionally build the DeDi env-var block. Empty if you skipped the
# DeDi step; populated with the auth-method-appropriate vars otherwise.
DEDI_ENV=()
if [ -n "${OPENCRED_DEDI_BASE_URL:-}" ]; then
  DEDI_ENV=(
    -e OPENCRED_DEDI_BASE_URL="$OPENCRED_DEDI_BASE_URL"
    -e OPENCRED_DEDI_AUTH_TYPE="$OPENCRED_DEDI_AUTH_TYPE"
    -e OPENCRED_DEDI_NAMESPACE="$OPENCRED_DEDI_NAMESPACE"
  )
  if [ "${OPENCRED_DEDI_AUTH_TYPE:-}" = "api-key" ]; then
    DEDI_ENV+=( -e OPENCRED_DEDI_API_KEY="$OPENCRED_DEDI_API_KEY" )
  elif [ "${OPENCRED_DEDI_AUTH_TYPE:-}" = "bearer" ]; then
    DEDI_ENV+=(
      -e OPENCRED_DEDI_EMAIL="$OPENCRED_DEDI_EMAIL"
      -e OPENCRED_DEDI_PASSWORD="$OPENCRED_DEDI_PASSWORD"
    )
  fi
fi

docker run -d \
  --name opencred \
  -p 3100:3100 \
  -e OPENCRED_API_KEY="$OPENCRED_API_KEY" \
  -e OPENCRED_KEY_PATH=/secrets/issuer-key.pem \
  -e OPENCRED_KEY_LABEL=bootcamp-issuer \
  -e OPENCRED_LOG_LEVEL=info \
  -v "$HOME/opencred-bootcamp/keys/issuer-key.pem:/secrets/issuer-key.pem:ro" \
  "${DEDI_ENV[@]}" \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  opencred:bootcamp
```

> The `"${DEDI_ENV[@]}"` placeholder expands to the env-var block built
> by the preamble above. If you set `OPENCRED_DEDI_BASE_URL` in §3a it
> contains 4 (api-key) or 5 (bearer) `-e VAR=...` pairs; if you skipped
> §3a the array is empty and the docker run is identical to the
> DeDi-disabled form.

Watch the logs to confirm the key loaded:

```bash
docker logs -f opencred
# Ctrl-C once you see "OpenCred server listening" and a key fingerprint.
```

Then probe `/v1/health` (this is **public** — it is the only protected path the
container exposes without an auth header, so orchestrators can liveness-check
without holding the API key):

```bash
curl -s http://localhost:3100/v1/health | jq
```

You want to see:

```json
{
  "status": "ok",
  "ready": true,
  "signingKeyLoaded": true,
  "dediConfigured": false,
  "timestamp": "..."
}
```

If `signingKeyLoaded: false`, the server is up but **cannot sign**. The key
file isn't readable inside the container. Jump to §8.

`dediConfigured` will be `true` if you completed §3a and `false` otherwise.
Both are fine for the core flow — §5 and §6a/§6b never touch DeDi. The
DeDi-dependent stretch sections (§7c revocation, §7d key publish/resolve)
will return `503 DEDI_NOT_CONFIGURED` if you set `dediConfigured: false`;
either repeat §3a + restart the container, or skip those sections.

Now confirm the API key works on a protected endpoint:

```bash
curl -s http://localhost:3100/v1/keys \
  -H "Authorization: Bearer $OPENCRED_API_KEY" | jq
```

You should see one entry with a `did:key:...` id, an `algorithm` of `P-256`,
`type: "software"`, and `source: "software-file"`. Note the `id` — that DID is
your **issuer DID** for the next step. Save it:

```bash
export ISSUER_DID="$(curl -s http://localhost:3100/v1/keys \
  -H "Authorization: Bearer $OPENCRED_API_KEY" | jq -r '.keys[0].id')"
echo "$ISSUER_DID"
```

### 5. Issue and verify your first credential

We'll use the bundled `functional-identity/v1` schema — minimal required
fields, easy to demo.

> **Postman users**: every request in this section and the next is in
> [`postman-collection.json`](postman-collection.json). The `GET /v1/keys` request
> already auto-saved your issuer DID into the `issuerDid` collection
> variable, so the issue requests work immediately. The issue requests in
> turn auto-save the credential into `lastCredential` for the verify
> request. Just click **Send** in order: `GET /v1/keys` → `POST /v1/credentials/issue (data-integrity)` → `POST /v1/credentials/verify`.
> The curl examples below are the same calls in shell form.

**Issue:**

```bash
curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"schemaId\": \"functional-identity/v1\",
    \"issuerDid\": \"$ISSUER_DID\",
    \"credentialSubject\": {
      \"name\": \"Jane Doe\",
      \"role\": \"Bootcamp Attendee\",
      \"validFrom\": \"2026-04-26T00:00:00Z\"
    },
    \"validFrom\": \"2026-04-26T00:00:00Z\",
    \"validUntil\": \"2027-04-26T00:00:00Z\",
    \"proofFormat\": \"data-integrity\"
  }" | tee credential.json | jq .credential
```

Now you have a signed VC on disk. Look at the `proof` block — the
`verificationMethod` points back to your DID, and the `proofValue` is the EC
signature over the canonicalized credential.

**Verify** the credential you just issued:

```bash
# The verify endpoint takes the credential as a JSON-stringified body field.
jq '{credential: (.credential | tostring)}' credential.json | \
  curl -s http://localhost:3100/v1/credentials/verify \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" \
    -d @- | jq
```

You want `"valid": true` and a `checks` array where every entry has
`passed: true`. The check names will include `signature` and `date`.

**Tamper test** (do this — it is the demo punchline):

```bash
# Change one character of the subject name and re-verify.
jq '.credential.credentialSubject.name = "Jane Tampered"' credential.json | \
  jq '{credential: (.credential | tostring)}' | \
  curl -s http://localhost:3100/v1/credentials/verify \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" \
    -d @- | jq
```

`valid` flips to `false`, the signature check fails. This is the moment the
"why VCs?" question answers itself — the credential is portable, but it is
also tamper-evident without phoning home to anyone.

### 6a. Issue a credential against your own pasted schema

The 34 bundled schemas cover common cases, but most users want to issue something tailored to their own use case. The server accepts a custom JSON Schema directly in the request body — no need to fork the repo or publish to a registry first.

Use `inlineSchema` instead of (or alongside) `schemaId`:

```bash
curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"inlineSchema\": {
      \"\$id\": \"https://example.org/schemas/training-cert/v1.json\",
      \"title\": \"Training Certificate\",
      \"type\": \"object\",
      \"required\": [\"name\", \"course\", \"passedOn\"],
      \"properties\": {
        \"name\":     { \"type\": \"string\", \"minLength\": 1 },
        \"course\":   { \"type\": \"string\", \"minLength\": 1 },
        \"passedOn\": { \"type\": \"string\", \"format\": \"date\" },
        \"score\":    { \"type\": \"number\", \"minimum\": 0, \"maximum\": 100 }
      }
    },
    \"issuerDid\": \"$ISSUER_DID\",
    \"credentialSubject\": {
      \"name\": \"Jane Doe\",
      \"course\": \"Bootcamp 101\",
      \"passedOn\": \"2026-04-27\",
      \"score\": 95
    },
    \"validFrom\": \"2026-04-27T00:00:00Z\",
    \"proofFormat\": \"vc-jwt\"
  }" | jq
```

The server compiles the schema, validates `credentialSubject` against it,
and writes the schema's `$id` (or a base64 data-URI fallback if you don't
include one) into the credential's `credentialSchema` block so verifiers
can fetch it later.

Things worth knowing:

- **Either-or, or both.** When `inlineSchema` is present, `schemaId` is
  optional. If you supply both, the inline schema wins for validation and
  for `credentialSchema.id`.
- **Subject-only or envelope.** The schema can describe just the
  `credentialSubject` shape (the example above) or wrap a full W3C VC 2.0
  envelope with `properties.credentialSubject` — the server detects the
  shape and validates the subject either way.
- **Validation is real.** Drop a required field, make `score` a string
  instead of a number, etc. — the server returns `400
  SCHEMA_VALIDATION_ERROR` with `validationErrors[]` exactly like it does
  for built-in schemas.
- **Defense-in-depth still applies.** A pasted schema that contains a
  string starting with `-----BEGIN ... PRIVATE KEY-----` (in any nested
  field — `description`, `examples`, etc.) is rejected with 400 before the
  schema is even compiled.
- **For data-integrity proofs**, also pass `inlineContext` with a JSON-LD
  context document; without it, RDFC-1.0 safe mode rejects undefined
  terms. `vc-jwt` and `sd-jwt-vc` don't need a context.

### 6b. Try a few proof formats

Repeat the issue call with `"proofFormat": "vc-jwt"` and
`"proofFormat": "sd-jwt-vc"` and observe how the response shape changes:

| Proof format | Response shape | Use case |
|---|---|---|
| `data-integrity` | JSON-LD VC with a `proof` object | Default for human-readable VCs |
| `vc-jwt` | Compact JWS string in `credential` | Smaller, JOSE-stack interop |
| `sd-jwt-vc` | Compact `~`-separated string | Selective disclosure (use `selectiveDisclosureClaims`) |

For SD-JWT, also pass:

```json
"selectiveDisclosureClaims": ["/credentialSubject/role"]
```

### 6c. Package the credential as a PDF / QR code

There are two paths — pick whichever feels more natural:

**A. One-call: ask for packaging at issue time.** Add `packageFormats`
(and optional `customization`) to the issue request body and the response
includes a `packagedOutputs[]` alongside the signed credential. Postman:
**Issue & Verify → POST /v1/credentials/issue (data-integrity + inline
package)**.

**B. Separate-step: re-render an already-issued credential.**
`POST /v1/credentials/package` takes the credential and the same
`customization` block. Postman:
**Packaging → POST /v1/credentials/package (auto from {{lastCredential}})**
— a pre-request script grabs whatever shape the last issue request
returned and posts it correctly.

Either path produces the same `outputs[]`/`packagedOutputs[]` array.

#### Works with all three proof formats

| `proofFormat` | What `credential` looks like in the request | What the QR encodes |
|---|---|---|
| `data-integrity` | JSON-LD VC object | PixelPass-compressed VC JSON, `OPENCRED1:` prefixed |
| `vc-jwt` | JSON-LD VC object (the JWT is embedded as `proof.jwt`) | Same as above (the VC wraps the JWT) |
| `sd-jwt-vc` | Compact `~`-separated string | The raw token, embedded verbatim |

For `sd-jwt-vc`, the server decodes the JWT payload offline (no
signature verification — packaging is a rendering step) to drive the
PDF certificate layout, and embeds the original token verbatim into the
QR code so any verifier scanning it runs a real cryptographic check
against your issuer's public key.

#### Output formats

| `format` | `mimeType` | `encoding` | `data` field |
|---|---|---|---|
| `qr-png` | `image/png` | `utf-8` ⚠️ | `data:image/png;base64,<...>` (a data URL — encoding is `utf-8` because the data field itself is a string) |
| `qr-svg` | `image/svg+xml` | `utf-8` | Inline SVG XML |
| `pdf` | `application/pdf` | `base64` | Pure base64 (no `data:` prefix) |
| `json` | `application/json` | `utf-8` | The signed VC pretty-printed (data-integrity / vc-jwt), or `{"format":"sd-jwt-vc","credential":"<token>"}` (sd-jwt-vc) |

The PDF and JSON come back with `.json` / `.pdf` filename suggestions
(plain — not `.jsonld`), so a double-click opens them in Preview / your
editor without OS-level fuss.

#### Decoding the response on the command line

Save the Postman response to a file (right-click → "Save response to
file"), then:

```bash
# qr-png — strip the data-URL prefix first, then base64-decode:
jq -r '.outputs[]
       | select(.format=="qr-png")
       | .data
       | sub("^data:image/png;base64,"; "")' response.json \
  | base64 -d > qr.png

# pdf — pure base64, decode directly:
jq -r '.outputs[] | select(.format=="pdf") | .data' response.json \
  | base64 -d > certificate.pdf

# qr-svg — already utf-8 SVG, just dump:
jq -r '.outputs[] | select(.format=="qr-svg") | .data' response.json \
  > qr.svg

# json — pretty-printed already:
jq -r '.outputs[] | select(.format=="json") | .data' response.json \
  > credential.json

# Open them all:
open certificate.pdf qr.png qr.svg
```

(For the inline-package path, replace `.outputs[]` with `.packagedOutputs[]`.)

#### Customization

All fields under `customization` are optional. The ones worth knowing:

| Field | Type | What it does |
|---|---|---|
| `primaryColor` | `#rrggbb` hex | Border + section headings |
| `secondaryColor` | hex | Sub-headings |
| `textColor` | hex | Body text |
| `labelColor` | hex | Field labels |
| `backgroundColor` | hex | Page background |
| `issuerDisplayName` | string ≤200 | Replaces the issuer DID under "ISSUED BY". **Use this exact key — `issuerName` is silently dropped.** |
| `logoDataUri` | `data:image/...;base64,...` | Logo image, rendered under the issuer name |
| `logoWidth` / `logoHeight` | integer 10–200 | Logo dimensions in points |
| `sealDataUri` | `data:image/...;base64,...` | Seal image, bottom-right of the certificate |
| `footerText` | string ≤500 | The line below "Digital Signature". Pass `""` to suppress entirely. Default is a generic verification disclaimer. |

#### Per-format failures don't kill the whole response

If a specific format fails (e.g. the QR code's compressed payload exceeds
the QR data capacity), the failure shows up in `errors[]` with the format
and message — the rest of the formats still come back. The HTTP response
itself is `200 OK` either way.

### 7. Stretch: Docker Compose, hardening, batch issuance

#### 7a. Compose, the lazy way

The repo ships a hardened `docker-compose.yml` — read-only rootfs, all caps
dropped except `NET_BIND_SERVICE`, `no-new-privileges`, a `/v1/health` probe.

```bash
cd /path/to/opencred  # the repo root
cp .env.example .env
$EDITOR .env          # set OPENCRED_API_KEY and OPENCRED_KEY_PATH

# Mount the key by editing the volumes block in docker-compose.yml:
#   volumes:
#     - ./keys/issuer-key.pem:/app/keys/issuer-key.pem:ro

docker compose up -d
docker compose logs -f server
```

Set `OPENCRED_KEY_PATH=/app/keys/issuer-key.pem` in your `.env` to match the
mount target.

#### 7b. CLI mode (no server at all)

The same crypto stack ships as a CLI. Useful for CI/CD or air-gapped issuance.

```bash
docker run --rm \
  -v "$HOME/opencred-bootcamp/keys/issuer-key.pem:/secrets/key.pem:ro" \
  -v "$PWD:/work" \
  --entrypoint node \
  opencred:bootcamp \
  apps/server/dist/cli.js issue \
    --schema functional-identity/v1 \
    --input /work/subject.json \
    --key /secrets/key.pem \
    --proof-format vc-jwt \
    --output /work/cli-credential.json
```

Where `subject.json` is `{ "name": "Alice", "role": "Auditor", "validFrom": "2026-04-26T00:00:00Z" }`.

There is also `opencred verify`, `opencred batch` (for CSV-driven bulk
issuance, capped by `OPENCRED_BATCH_ROW_LIMIT`), and `opencred config validate`
for CI pre-flight checks.

#### 7c. DeDi: revocation hashes, then a live revoke

OpenCred uses [DeDi](https://github.com/dhiway/dedi) as the revocation registry
when one is configured. There are two layers, and you should teach them in
order:

1. **The hash itself** — `POST /v1/credentials/revocation-hash` is JCS
   canonicalization + SHA-256. It works on every container, with or without
   DeDi configured. This is the artifact you publish.
2. **DeDi publish/query** — `POST /v1/credentials/revoke` and
   `POST /v1/credentials/revocation-status` actually talk to DeDi. Both return
   `503 DEDI_NOT_CONFIGURED` until you wire it up.

Step 1 runs on your own container without any external setup — start there.

```bash
curl -s http://localhost:3100/v1/credentials/revocation-hash \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d @credential.json | jq
# => { "revocationHash": "…64 hex chars…", "hash": "…same…" }
```

That hash is what gets published to DeDi later. Note that the request body is
the credential `{ "credential": {...} }` — you can pipe `credential.json`
directly because that file already has that shape from §5.

If you completed §3a, your container is **already DeDi-configured** —
you can skip straight to the issue + revoke flow below. Confirm:

```bash
curl -s http://localhost:3100/v1/health | jq .dediConfigured
# => true
```

If `dediConfigured` is `false`, you skipped §3a. Either:

- (a) Repeat §3a to export the DeDi env vars, then `docker rm -f opencred` and re-run §4 — same `docker run` command; the `DEDI_ENV` preamble now populates the array.
- (b) Skip §7c and §7d entirely. Everything else still works.

**Reference: DeDi env vars** (the same ones you exported in §3a):

| Env var | Required when DeDi is on | Notes |
|---|---|---|
| `OPENCRED_DEDI_BASE_URL` | always | DeDi instance URL, e.g. `https://dedi.example.org` |
| `OPENCRED_DEDI_AUTH_TYPE` | always | `api-key` or `bearer` |
| `OPENCRED_DEDI_API_KEY` | when `AUTH_TYPE=api-key` | The DeDi API token |
| `OPENCRED_DEDI_EMAIL` | when `AUTH_TYPE=bearer` | DeDi account email |
| `OPENCRED_DEDI_PASSWORD` | when `AUTH_TYPE=bearer` | DeDi account password |
| `OPENCRED_DEDI_NAMESPACE` | always | Default namespace for all DeDi calls |
| `OPENCRED_DEDI_TIMEOUT_MS` | optional | Default `10000`, range 1000–30000 |

> The server validates these at startup. If you set `OPENCRED_DEDI_BASE_URL`
> but forget `OPENCRED_DEDI_AUTH_TYPE` or `OPENCRED_DEDI_NAMESPACE`, the
> container exits immediately with `ConfigError`. Same if `AUTH_TYPE=api-key`
> and `OPENCRED_DEDI_API_KEY` is unset. Validate with `opencred config
> validate` before you `docker run`.

Now issue a credential with a `credentialStatus` block — pass
`revocationRegistryUrl` in the issue body so the server attaches a `dedi`-typed
status entry. The server generates a `urn:uuid:...` credential id and a
matching SHA-256 revocation hash:

```bash
curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"schemaId\": \"functional-identity/v1\",
    \"issuerDid\": \"$ISSUER_DID\",
    \"credentialSubject\": {
      \"name\": \"Jane Doe\",
      \"role\": \"Bootcamp Attendee\",
      \"validFrom\": \"2026-04-26T00:00:00Z\"
    },
    \"validFrom\": \"2026-04-26T00:00:00Z\",
    \"proofFormat\": \"data-integrity\",
    \"revocationRegistryUrl\": \"https://your-dedi-instance.example.org\"
  }" | tee revokable.json | jq '.credential.credentialStatus'
```

Compute the hash, revoke it via DeDi, then query the status — that round trip
is the whole point of the demo:

```bash
# Compute the hash for the revokable credential.
HASH=$(jq '{credential: .credential}' revokable.json | \
  curl -s http://localhost:3100/v1/credentials/revocation-hash \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" -d @- | jq -r .revocationHash)
echo "Hash: $HASH"

# Publish to DeDi.
curl -s http://localhost:3100/v1/credentials/revoke \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"hash\": \"$HASH\"}" | jq

# Query DeDi for the status.
curl -s http://localhost:3100/v1/credentials/revocation-status \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"hash\": \"$HASH\"}" | jq
```

The credential is now revoked at the DeDi layer. Verifiers that consult the
registry will see it; verifiers that only check the signature will not (which
is part of the point — revocation is a separate trust check, intentionally).

> **Operator note**: the API key in `OPENCRED_DEDI_API_KEY` is a bearer-style
> credential against your DeDi instance, not against OpenCred. It should be
> issued from your DeDi admin UI, scoped to the namespace you intend to use,
> and rotated independently of `OPENCRED_API_KEY`. Treat it like a database
> credential — never bake it into the image, never commit it to git, mount it
> via secrets management in production (Docker secrets, AWS SSM, etc.).

#### 7d. Publish a public key (DID document) to DeDi

Same DeDi instance, same namespace, different registry. The public-key
registry lets verifiers resolve an issuer's DID document from DeDi instead
of relying on `did:web` HTTPS lookups or trusting a third-party DID
registrar.

```bash
# Publish — body is { did, document, namespace? }. The "document" is a
# standard W3C DID Core document; verificationMethod entries hold public
# keys only. The server's defense-in-depth guard rejects any nested PEM
# private-key block before the request reaches DeDi.
curl -s http://localhost:3100/v1/keys/publish \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:web:bootcamp.example.org",
    "document": {
      "@context": "https://www.w3.org/ns/did/v1",
      "id": "did:web:bootcamp.example.org",
      "verificationMethod": [{
        "id": "did:web:bootcamp.example.org#key-1",
        "type": "JsonWebKey2020",
        "controller": "did:web:bootcamp.example.org",
        "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
      }],
      "assertionMethod": ["did:web:bootcamp.example.org#key-1"]
    }
  }' | jq

# Resolve — body is { did, namespace? }. POST not GET so DIDs with colons
# don't have to be URL-encoded.
curl -s http://localhost:3100/v1/keys/resolve \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "did": "did:web:bootcamp.example.org" }' | jq
```

`/v1/keys/publish` returns `{ published: true, recordName, namespace }` on
success. `/v1/keys/resolve` returns `{ did, document, resolvedAt }`. Both
endpoints return `503 DEDI_NOT_CONFIGURED` if the DeDi env vars from §7c
aren't set.

> **The takeaway**: once you've run §7d on a VM you control, you can stop serving a `did:web` document from a webserver entirely — DeDi becomes the resolution endpoint. The signature on every issued VC is the same as before; only how verifiers find the public key changes.

#### 7e. Cloud HSM (read-through, not a live exercise)

For production, file-based keys are usually the wrong answer. Here's the env shape so you know what to reach for:

```bash
# AWS KMS (uses default credential chain)
OPENCRED_KMS_PROVIDER=aws
OPENCRED_KMS_KEY_ARN=arn:aws:kms:us-east-1:...:key/...

# Azure Key Vault (uses DefaultAzureCredential)
OPENCRED_KMS_PROVIDER=azure
OPENCRED_AZURE_KEY_VAULT_URL=https://my-vault.vault.azure.net/
OPENCRED_AZURE_KEY_NAME=opencred-issuer

# GCP Cloud KMS (uses ADC)
OPENCRED_KMS_PROVIDER=gcp
OPENCRED_GCP_KMS_KEY_NAME=projects/p/locations/.../cryptoKeyVersions/1
```

Same `/v1/keys` shape, same issuance API — the signer just lives in a
different place. Send anyone interested to `docs/docker/cloud-hsm.md`.

#### 7e. Mid-session DeDi: ensure a namespace at runtime

If you skipped §3a (started the container in DeDi-disabled mode) but
later decide you want DeDi for a §7c revocation or §7d key publish,
you have two options:

1. **Stop and re-run the container** with the four `OPENCRED_DEDI_*`
   env vars set (the §3a/§4 flow). Health check will then show
   `dediConfigured: true`. This is the recommended path because it
   re-creates the singleton with proper auth.
2. **(Already-running container, you only need a different namespace)** —
   if the container *is* DeDi-configured but you want to ensure a
   fresh namespace exists for your record, hit the runtime endpoint:

   ```bash
   curl -sS -X POST http://localhost:3100/v1/dedi/namespace/ensure \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $OPENCRED_API_KEY" \
     -d '{"namespace":"did:web:my-tenant.example.org"}' | jq
   ```

   ```json
   {
     "namespace": "did:web:my-tenant.example.org",
     "registries": [
       "vc-revocation-registry",
       "public_key_registry",
       "schema_registry",
       "context_registry"
     ]
   }
   ```

The endpoint is idempotent — calling it for an already-ensured
namespace returns the same shape with `200 OK`. It returns
`503 DEDI_NOT_CONFIGURED` if the container was started without DeDi
env vars (in which case go with option 1).

The Postman collection has this under **DeDi runtime → POST
/v1/dedi/namespace/ensure**.

### 8. Troubleshooting cheat sheet

| Symptom | Likely cause | Fix |
|---|---|---|
| Container exits within ~1 second | Required env var missing or invalid (Zod validation) | `docker logs opencred` — the offending field is named in the error |
| `OPENCRED_API_KEY is required` at startup | Neither the API key nor `OPENCRED_DEV_MODE_NO_AUTH=true` was set | Set the API key. Don't reach for the dev-mode flag during the bootcamp. |
| `/v1/health` returns `503`, `signingKeyLoaded: false` | Key file is not at the path the container expects, or the `node` user can't read it | Re-check the `-v` mount, confirm the file is `0600` *and* readable by uid 1000 (the `node` user), or use `0644` if shared on Docker Desktop |
| `401 AUTHENTICATION_ERROR` on every call | Missing `Authorization: Bearer …` header, wrong token, or shell trimmed the token | Re-export `OPENCRED_API_KEY` and pass it explicitly |
| `400 VALIDATION_ERROR — field "privateKey" is forbidden` | You pasted key material into a request body | The server rejects any field named `privateKey`, `pkcs8`, `pfx`, etc., and any string starting with `-----BEGIN ... PRIVATE KEY-----`. This is the defense-in-depth guard — don't disable it, fix the client. |
| `400 SCHEMA_VALIDATION_ERROR` | `credentialSubject` does not satisfy the JSON Schema for the chosen `schemaId` | Look at the `validationErrors` array in the response — it will list the missing/wrong fields. For `functional-identity/v1`, the required fields in `credentialSubject` are `name`, `role`, `validFrom`. |
| `500 CRYPTO_ERROR` on `data-integrity` | Tried to use `data-integrity` with an RSA key | Use `vc-jwt` or `sd-jwt-vc`, or regenerate the key as EC P-256 |
| `Schema 'education' not found` (or any 404 / "no such schema") | That id is not in the built-in registry | List what's actually available: `curl -s http://localhost:3100/v1/schemas -H "Authorization: Bearer $OPENCRED_API_KEY" \| jq '.[].id'` |
| `503 DEDI_NOT_CONFIGURED` on `/v1/credentials/revoke` or `/revocation-status` | DeDi env vars are missing — `dediConfigured: false` in `/v1/health` | Set `OPENCRED_DEDI_BASE_URL`, `OPENCRED_DEDI_AUTH_TYPE`, `OPENCRED_DEDI_NAMESPACE`, and the matching auth pair (`OPENCRED_DEDI_API_KEY` for `api-key`, or `OPENCRED_DEDI_EMAIL`+`OPENCRED_DEDI_PASSWORD` for `bearer`), then restart the container |
| Container exits with `OPENCRED_DEDI_AUTH_TYPE is required when OPENCRED_DEDI_BASE_URL is set` (or similar) | Partial DeDi config | Either set the full DeDi quartet (URL + auth-type + namespace + auth secret) or unset `OPENCRED_DEDI_BASE_URL` entirely. Run `opencred config validate` to catch this before `docker run`. |
| Build hangs at "fetching pnpm" | Conference Wi-Fi blocking npmjs.org | Use a phone hotspot, or distribute a pre-built image via `docker save`/`docker load` |
| `port is already allocated` | Something is on 3100 already | Pick a different host port: `-p 3200:3100`, then point curl at `:3200`. The server still listens on 3100 inside the container. |

### 9. What you should have

- A working `opencred:bootcamp` image and a signing key you own.
- The Docker operator guide at <https://opencred.gitbook.io/docs> bookmarked — the `api-reference`, `deployment`, and `cloud-hsm` pages cover everything beyond what this bootcamp shows.
- The mental model: **OpenCred runs in your infrastructure, with your keys, signing your credentials.** There is no `api.opencred.com` to call. NFH Trust Labs operates no hosted endpoints.
- A next-step idea: pick a credential type that matches your own use case (employment letter, training certificate, role assertion) and design the `credentialSubject`. The custom-schema flow in §6 is exactly for this.

### 10. Cleanup

```bash
docker rm -f opencred
docker image rm opencred:bootcamp   # optional
# Keep keys/issuer-key.pem if they want to reuse it; otherwise:
shred -u ~/opencred-bootcamp/keys/issuer-key.pem 2>/dev/null \
  || rm -P ~/opencred-bootcamp/keys/issuer-key.pem
```

---

## Appendix A — One-screen quick-reference card (print this)

```
# Pull the image (once)
docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
docker tag  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest opencred:bootcamp

# Key + token
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out keys/issuer-key.pem
chmod 600 keys/issuer-key.pem
export OPENCRED_API_KEY="$(openssl rand -base64 32)"

# Optional: DeDi — skip if you don't have access. Uncomment to use:
# export OPENCRED_DEDI_BASE_URL=https://your-dedi.example.org
# export OPENCRED_DEDI_AUTH_TYPE=api-key
# export OPENCRED_DEDI_API_KEY=paste-your-token
# export OPENCRED_DEDI_NAMESPACE=your-namespace-id   # e.g. did:web:did.cord.network:xyz (unverified) or xyz.org (verified)

# Build DEDI_ENV (empty if no DeDi exports above)
DEDI_ENV=()
if [ -n "${OPENCRED_DEDI_BASE_URL:-}" ]; then
  DEDI_ENV=(
    -e OPENCRED_DEDI_BASE_URL="$OPENCRED_DEDI_BASE_URL"
    -e OPENCRED_DEDI_AUTH_TYPE="$OPENCRED_DEDI_AUTH_TYPE"
    -e OPENCRED_DEDI_NAMESPACE="$OPENCRED_DEDI_NAMESPACE"
  )
  if [ "${OPENCRED_DEDI_AUTH_TYPE:-}" = "api-key" ]; then
    DEDI_ENV+=( -e OPENCRED_DEDI_API_KEY="$OPENCRED_DEDI_API_KEY" )
  elif [ "${OPENCRED_DEDI_AUTH_TYPE:-}" = "bearer" ]; then
    DEDI_ENV+=( -e OPENCRED_DEDI_EMAIL="$OPENCRED_DEDI_EMAIL" \
                -e OPENCRED_DEDI_PASSWORD="$OPENCRED_DEDI_PASSWORD" )
  fi
fi

# Run
docker run -d --name opencred -p 3100:3100 \
  -e OPENCRED_API_KEY="$OPENCRED_API_KEY" \
  -e OPENCRED_KEY_PATH=/secrets/issuer-key.pem \
  -v "$PWD/keys/issuer-key.pem:/secrets/issuer-key.pem:ro" \
  "${DEDI_ENV[@]}" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  opencred:bootcamp

# Health (public)
curl -s http://localhost:3100/v1/health | jq

# Issuer DID
ISSUER_DID="$(curl -s http://localhost:3100/v1/keys \
  -H "Authorization: Bearer $OPENCRED_API_KEY" | jq -r '.keys[0].id')"

# Issue
curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"schemaId":"functional-identity/v1","issuerDid":"'"$ISSUER_DID"'",
       "credentialSubject":{"name":"Jane Doe","role":"Bootcamp Attendee",
       "validFrom":"2026-04-26T00:00:00Z"},
       "validFrom":"2026-04-26T00:00:00Z","proofFormat":"data-integrity"}' \
  | tee credential.json | jq

# Verify
jq '{credential: (.credential | tostring)}' credential.json \
  | curl -s http://localhost:3100/v1/credentials/verify \
      -H "Authorization: Bearer $OPENCRED_API_KEY" \
      -H "Content-Type: application/json" -d @- | jq
```

---

## Appendix B — Endpoint cheat sheet

All under `/v1/*`. Auth: `Authorization: Bearer $OPENCRED_API_KEY` except where noted. The legacy unprefixed routes (`/health`, `/credentials/issue`, …) also exist for backwards compatibility, but **always use `/v1` in new code**.

| Method + path | Auth | What it does |
|---|---|---|
| `GET /v1/health` | public | Liveness + `signingKeyLoaded` flag |
| `GET /v1/metrics` | public | Prometheus metrics |
| `GET /v1/keys` | required | Metadata about the loaded signer (no key material) |
| `GET /v1/schemas` | required | Built-in schema registry — useful when an `id` is rejected |
| `POST /v1/credentials/issue` | required | Build, validate, sign a VC. Pass either `schemaId` (built-in) or `inlineSchema` (your pasted JSON Schema), or both. |
| `POST /v1/credentials/verify` | required | Verify a VC (any of the three proof formats) |
| `POST /v1/credentials/batch` | required | CSV-driven bulk issuance |
| `POST /v1/credentials/revocation-hash` | required | Compute the SHA-256 hash for a DeDi revocation entry |
| `POST /v1/credentials/revoke` | required | Revoke a credential via DeDi (only when DeDi is configured) |
| `POST /v1/credentials/revocation-status` | required | Current revocation status (DeDi required) |
| `POST /v1/credentials/package` | required | Render packaged outputs (QR, PDF, etc.) for a signed VC |
| `POST /v1/keys/publish` | required | Publish a DID document to the DeDi `public_key_registry` (DeDi required) |
| `POST /v1/keys/resolve` | required | Resolve a DID document from DeDi (DeDi required) |
