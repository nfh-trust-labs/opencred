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

> **About the image URL.** The `nfh-trust-labs/opencred` segment in the GHCR
> path is the *source repo's* namespace, not a visibility hint. GHCR namespaces
> every container under the repo that publishes it, so the image inherits the
> source repo's name even though the image itself is **public** and
> anonymously pullable. You do not need a token or read access to
> `nfh-trust-labs/opencred` to `docker pull` it; if your `docker pull` is
> asking for credentials, run `docker logout ghcr.io` first to clear any
> stale tokens in `~/.docker/config.json` and retry.

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

> **Schema-collision caveat.** "Reused if they already exist" is only safe when
> the pre-existing registry was created by OpenCred (or with a schema-shape
> identical to what OpenCred publishes). DeDi backends ship built-in JSON
> Schemas for some registry names — notably `public_key.json` with shape
> `{public_key_id, publicKey, keyType, ...}`, which is **not** the shape
> OpenCred writes (`{did, document?, keyStatus}` — `document` is omitted
> for `did:key` records, and `keyStatus` is `"current"` or `"rotated"`).
> If a DeDi operator pre-creates a `public_key_registry` using the
> built-in catalogue schema before OpenCred boots, every `/v1/keys/publish`
> call will fail with a `400 "Record data does not match the registry
> schema"` from DeDi's AJV check. The same applies to any other registry
> name DeDi has a built-in schema for. Easiest mitigation: let OpenCred
> create the registries on first boot, and if you do pre-provision, make
> sure the schema you attach matches what OpenCred writes (look at
> `packages/dedi-client/src/adapter/client.ts` for the canonical shapes).

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

> **Heads-up — the issuer's DID is not published to DeDi automatically.**
> Container startup creates the four empty registries (`vc-revocation-registry`,
> `public_key_registry`, `schema_registry`, `context_registry`) and loads
> your signing key into memory, but it does not write your DID into
> `public_key_registry`. The `Issuer identity configured` log line you see
> at boot is purely an in-memory configuration message. To make verifiers
> discover your public key via DeDi, you have to explicitly call
> `POST /v1/keys/publish` (see §7d). Until then, `/v1/keys/resolve` returns
> 404.
>
> `OPENCRED_DEDI_HOST_DID_DOC=true` is documented as the "DeDi-hosted
> `did.json`" flag for did:web issuers, but **it's a no-op at startup
> today** — the validation passes but no publish actually happens. Until
> that gap is closed (tracked as an open follow-up issue), assume you need
> the explicit `/v1/keys/publish` call for any DID method.

Now confirm the API key works on a protected endpoint:

```bash
curl -s http://localhost:3100/v1/keys \
  -H "Authorization: Bearer $OPENCRED_API_KEY" | jq
```

You should see one entry with a `did:key:...` id, an `algorithm` of `P-256`,
`type: "software"`, and `source: "software-file"`. The `id` field is the
**verification-method ID** — DID plus a `#fragment` identifying the
specific key — so strip the fragment to get the bare DID for the next
step:

```bash
export ISSUER_DID="$(curl -s http://localhost:3100/v1/keys \
  -H "Authorization: Bearer $OPENCRED_API_KEY" | jq -r '.keys[0].id | split("#")[0]')"
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
> request. Just click **Send** in order: `GET /v1/keys` → `POST /v1/credentials/issue (vc-jwt)` → `POST /v1/credentials/verify`.
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
    \"proofFormat\": \"vc-jwt\"
  }" | tee credential.json | jq .credential
```

`vc-jwt` is the server's default and works with every bundled schema. We'll explore the JSON-LD-flavored `data-integrity` and selective-disclosure `sd-jwt-vc` formats in §6b.

Now you have a signed VC on disk. The `proof` block carries a compact JWS in `proof.jwt` — header.payload.signature — signed by your issuer key over the credential payload.

**Verify** the credential you just issued:

```bash
# vc-jwt verification: send the compact JWS string (the .proof.jwt value)
# as the `credential` field. For data-integrity / sd-jwt-vc, see §6b for
# the matching input shapes.
jq -n --arg c "$(jq -r '.credential.proof.jwt' credential.json)" '{credential: $c}' | \
  curl -s http://localhost:3100/v1/credentials/verify \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" \
    -d @- | jq
```

You want `"valid": true` and a `checks` array where every entry has
`passed: true`. The check names will include `signature` and `date`.

> **PDF inputs.** `POST /v1/credentials/verify` also accepts a raw
> PDF body when the request carries `Content-Type: application/pdf`.
> Useful when you've already packaged a credential as a printable
> PDF in §6c and want to verify the PDF directly without re-extracting
> the JSON. See [Docker → API reference → `POST /v1/credentials/verify`](../docker/api-reference.md#post-v1credentialsverify).

**Tamper test** (do this — it is the demo punchline):

```bash
# Flip one character of the JWT signature segment and re-verify.
JWT=$(jq -r '.credential.proof.jwt' credential.json)
jq -n --arg c "${JWT%?}X" '{credential: $c}' | \
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

§5 used `vc-jwt` (the default). Repeat the issue call with
`"proofFormat": "data-integrity"` and `"proofFormat": "sd-jwt-vc"`
and observe how the response shape changes:

| Proof format | Response shape | Use case |
|---|---|---|
| `vc-jwt` (default) | Compact JWS in `proof.jwt` | Default — works with every schema, JOSE-stack interop |
| `data-integrity` | JSON-LD VC with a `proof` object holding a `proofValue` | When you want a self-describing JSON-LD credential. Requires a JSON-LD context that does not redefine W3C-protected terms; otherwise the server returns `CRYPTO_ERROR: Invalid JSON-LD syntax; tried to redefine a protected term`. |
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
**Issue & Verify → POST /v1/credentials/issue (vc-jwt + inline
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

### 6d. Try a different built-in schema: `electricity/v1`

`functional-identity/v1` is a deliberately minimal schema. The bundled
registry has 34 others — `GET /v1/schemas` lists them all. Switching
schemas is just an `id` swap, but each schema has its own required
fields and nested types. The `electricity/v1` schema (a Beckn-flavored
utility-customer credential) is a good worked example because it
hits two friction points first-time attendees often miss.

```bash
curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"schemaId\": \"electricity/v1\",
    \"issuerDid\": \"$ISSUER_DID\",
    \"credentialSubject\": {
      \"customerProfile\": {
        \"customerNumber\": \"BESCOM-1234567890\",
        \"meterNumber\": \"MTR-99887766\",
        \"meterType\": \"AMI\"
      },
      \"customerDetails\": {
        \"fullName\": \"Jane Doe\",
        \"installationAddress\": {
          \"address\": \"42 MG Road, Bengaluru\",
          \"area_code\": \"560001\",
          \"country\": { \"name\": \"India\", \"code\": \"IN\" }
        },
        \"serviceConnectionDate\": \"2024-04-15T00:00:00Z\"
      }
    },
    \"validFrom\": \"2026-04-26T00:00:00Z\",
    \"validUntil\": \"2027-04-26T00:00:00Z\",
    \"proofFormat\": \"vc-jwt\"
  }" | tee electricity-credential.json | jq .credential
```

Three things worth calling out:

- **`country` is an object, not a string.** Beckn's `Location.country`
  is `{ name?, code }` with `code` matching ISO 3166-1 alpha-2 (`^[A-Z]{2}$`).
  Passing `"country": "IN"` returns `400 SCHEMA_VALIDATION_ERROR` with
  `must be object`.
- **`serviceConnectionDate` is `date-time`, not `date`.** Pass a full
  ISO 8601 timestamp (`2024-04-15T00:00:00Z`). A bare date
  (`2024-04-15`) returns `must match format "date-time"`.
- **`meterType` is an enum.** Valid values: `AMR`, `AMI`,
  `Electromechanical`, `Forward`, `Reverse`, `Bidirectional`,
  `Prepaid`, `NetMeter`, `Other`. Anything else is rejected.

`proofFormat: vc-jwt` here is deliberate — `data-integrity` against
`electricity/v1` currently returns `CRYPTO_ERROR: Invalid JSON-LD
syntax; tried to redefine a protected term`, tracked as
[#596](https://github.com/nfh-trust-labs/opencred/issues/596). `vc-jwt`
is the server's default and works for every bundled schema.

`customerProfile` is the only required block under `credentialSubject`
— `customerDetails`, `consumptionProfile`, `generationProfile`, and
`storageProfile` are all optional. You can drop the `customerDetails`
block above for a minimal credential.

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
status entry. **The URL should be the canonical DeDi lookup endpoint for your
revocation registry, not the bare base URL** — it gets stamped directly into
the credential's `credentialStatus.statusListCredential` so a third-party
verifier (or anyone reading the VC) can resolve it. The lookup shape DeDi
serves is `https://<host>/dedi/lookup/<namespace>/<revocation-registry-name>`.

The server generates a `urn:uuid:...` credential id and a matching SHA-256
revocation hash:

```bash
# Substitute your DeDi host and the namespace you set in §3a.
# The revocation registry name is the OpenCred default unless you've
# changed it; see `OPENCRED_DEDI_REVOCATION_REGISTRY_NAME`.
REVOCATION_REGISTRY_URL="https://your-dedi-instance.example.org/dedi/lookup/${OPENCRED_DEDI_NAMESPACE}/vc-revocation-registry"

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
    \"proofFormat\": \"vc-jwt\",
    \"revocationRegistryUrl\": \"$REVOCATION_REGISTRY_URL\"
  }" | tee revokable.json | jq '.credential.credentialStatus'
```

> **Why the canonical lookup URL matters.** Verification still works end-to-end
> even if you pass a bare base URL — OpenCred's own verifier recomputes the
> hash and queries DeDi via the SDK, not by following the
> `credentialStatus.id` link. But that link gets serialized into the issued
> credential and is what a W3C-compliant third-party verifier will dereference.
> Pass the canonical URL so the credential is self-describing.

Compute the hash, revoke it via DeDi, then query the status — that round trip
is the whole point of the demo:

```bash
# Compute the hash for the revokable credential.
HASH=$(jq '{credential: .credential}' revokable.json | \
  curl -s http://localhost:3100/v1/credentials/revocation-hash \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" -d @- | jq -r .revocationHash)
echo "Hash: $HASH"

# Publish to DeDi. `reason` is an optional free-text descriptor (per the
# DeDi canonical revoke.json schema) — typical values are short tags like
# "key-compromised", "superseded", or "holder-request". When supplied, it
# is stored alongside the hash on the DeDi record and surfaced verbatim by
# /v1/credentials/revocation-status.
curl -s http://localhost:3100/v1/credentials/revoke \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"hash\": \"$HASH\", \"reason\": \"key-compromised\"}" | jq

# Query DeDi for the status. The response echoes `hash` and (if a reason
# was supplied at publish time) `reason`.
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

Same DeDi instance, same namespace, different registry. The
`public_key_registry` lets verifiers **discover an issuer's DID document
via DeDi** — OpenCred's verifier tries the canonical `did:web` HTTPS
endpoint first, and falls back to DeDi when the well-known URL is
unreachable. This means an issuer can stop hosting their own
`.well-known/did.json` and let DeDi serve as the discovery layer.

> **Heads-up — this step is explicit, not automatic.** Container startup
> only initializes the empty `public_key_registry`; it does not publish
> your issuer DID. The `Issuer identity configured` log line at boot
> means "the server is configured to sign with this DID," NOT "this DID
> is published to DeDi." Verifiers calling `/v1/keys/resolve` will
> return 404 until you run the `POST /v1/keys/publish` call below at
> least once.
>
> **Heads-up — key rotation under did:web is not yet supported.** Today,
> rotating a did:web signing key (swap `OPENCRED_KEY_PATH`, restart)
> produces signatures that nothing in DeDi or `.well-known/did.json`
> reflects, because there is no flow to update the hosted DID Document.
> Track [issue #619](https://github.com/nfh-trust-labs/opencred/issues/619)
> for the multi-key DID Document + `POST /v1/keys/rotate` design work
> (and the linked design spike doc) that closes this gap. Until then,
> keep `did:web` issuers on a stable key for the lifetime of the
> deployment.

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
success. `/v1/keys/resolve` returns `{ did, document?, keyStatus }` — and may
include a `proof` block when DeDi anchored the record to the CORD blockchain.
`document` is omitted for `did:key` records (the verifier derives it from
the DID itself); `keyStatus` is `"current"` for a freshly-published record
and flips to `"rotated"` after the desktop's auto-rotation hook runs (see
[Desktop → Key Management → Auto-rotation on key generation](../desktop/key-management.md#auto-rotation-on-key-generation)).
Both endpoints return `503 DEDI_NOT_CONFIGURED` if the DeDi env vars from §7c
aren't set.

> **The takeaway**: once you've run §7d, you can stop serving a `did:web` document from a webserver entirely — OpenCred's verifier falls back to DeDi automatically whenever the canonical endpoint is unreachable. The signature on every issued VC is the same as before; only the discovery path for the public key changes. To make this work for verifiers you don't control, they need to be running OpenCred (or any verifier that wires `createDeDiDIDWebFallback` into its resolver) and have the same `OPENCRED_DEDI_*` env vars set. Pure off-the-shelf did:web resolvers without DeDi awareness will still need the canonical HTTPS endpoint.

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

### 7e. Beyond the bootcamp — production hardening

The bootcamp drives a single container with the most ergonomic
defaults. Production deployments have more knobs. None of these are
required for the §1–§7 happy path — they're pointers to follow when
you outgrow the single-instance model.

- **Horizontal scale.** Swap `OPENCRED_JOB_STORE=memory` for `redis`
  and run multiple replicas behind a load balancer. Every replica
  can answer batch status reads regardless of which one received the
  POST. See [Docker → Deployment → Horizontal scale](../docker/deployment.md#horizontal-scale).

- **Read-only verify tier.** Set `OPENCRED_READ_ONLY=true` on a
  separate replica pool to refuse every write endpoint with
  `405 READ_ONLY_MODE`. These replicas have **no signing key** and
  exist only to serve verification traffic at high volume. See
  [Docker → Deployment → Read-tier deployment](../docker/deployment.md#read-tier-deployment).

- **Worker fleet.** `OPENCRED_BATCH_DISPATCH=queue` moves batch
  signing onto a BullMQ queue consumed by a separate `node
  dist/worker.js` process. Required when you want batch jobs to
  survive an API-process restart, or when you need to scale workers
  independently of the API. See
  [Docker → Deployment → Queue dispatch](../docker/deployment.md#queue-dispatch-worker-fleet--opencred_batch_dispatchqueue).

- **Webhooks.** Add `webhookUrl` (HTTPS) to a batch request to be
  notified when the job finishes. `OPENCRED_WEBHOOK_SECRET` (min 32
  chars) configures the HMAC-SHA256 signing key. Deliveries retry
  with exponential backoff and land in a DLQ on permanent failure.

- **Body caps and rate limits.** Tune `OPENCRED_MAX_BODY_BYTES`,
  `OPENCRED_MAX_BATCH_BODY_BYTES`,
  `OPENCRED_BATCH_MAX_RECORD_BYTES`, and the
  `OPENCRED_RATE_LIMIT_*` family to your traffic profile. See
  [Docker → API reference → Rate limits](../docker/api-reference.md#rate-limits)
  and the env-var table.

- **`@opencred/verify` SDK.** Verifiers who want to embed
  verification in their own Node.js service can install
  `@opencred/verify` instead of running the container. Zero-config
  handles `did:key` / `did:jwk` fully offline; pass a `dedi` block
  for revocation + `did:web` fallback. See
  [Docker overview](../docker/README.md#three-surfaces).

- **Tracing.** Set `OPENCRED_OTEL_ENABLED=true` plus the standard
  `OTEL_EXPORTER_OTLP_ENDPOINT` to ship critical-path spans
  (`batch.run`, `signer.sign`, `verify.credential`, `dedi.*`) to
  your collector. A sample Grafana dashboard ships at
  [docs/observability/grafana-dashboards/](../observability/grafana-dashboards/README.md).

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
| `409 DEDI_RECORD_EXISTS` on `/v1/credentials/revoke` (response body has a `hint` field) | The hash you're publishing is already revoked in `vc-revocation-registry` from a prior run. The DeDi record uses the hash as `record_name`, so re-revoking the same VC is a duplicate-key collision. | This is "success on a prior run" — confirm with `POST /v1/credentials/revocation-status` (the response `hint` points there). For a fresh revoke demo, issue a NEW credential with `revocationRegistryUrl` set: every issue mints a fresh `urn:uuid:` → fresh hash → no collision. |
| `409 DEDI_RECORD_EXISTS` on `/v1/keys/publish` (response body has a `hint` field) | This DID was already published in a prior run — `public_key_registry` uses the DID as `record_name`, so republishing the same DID is a duplicate-key collision. | Skip the publish and call `POST /v1/keys/resolve` instead (the response `hint` points there) — the previous publish landed and the document is available. To demo a fresh publish, use a unique `did:web:<your-domain>` you haven't published before. |
| Container exits with `OPENCRED_DEDI_AUTH_TYPE is required when OPENCRED_DEDI_BASE_URL is set` (or similar) | Partial DeDi config | Either set the full DeDi quartet (URL + auth-type + namespace + auth secret) or unset `OPENCRED_DEDI_BASE_URL` entirely. Run `opencred config validate` to catch this before `docker run`. |
| Startup log shows DeDi lookup URL with `%E2%80%9C` / `%E2%80%9D` wrapping your namespace (e.g. `/dedi/lookup/%E2%80%9Cverifaistudio.co%E2%80%9D` → `404 Namespace not found` → `401 Invalid API key`) | Your `OPENCRED_DEDI_NAMESPACE` (or API key) was pasted with **Unicode smart quotes** (`"…"` instead of ASCII `"…"`), usually from a chat app, docs page, or note-taking app that auto-corrects | Re-export with straight ASCII quotes — or no quotes at all if the value has no spaces: `export OPENCRED_DEDI_NAMESPACE=verifaistudio.co`. Verify before `docker run` with `printf '%s\n' "$OPENCRED_DEDI_NAMESPACE" \| od -c \| head -1` — anything other than plain ASCII bytes means a smart quote slipped in. |
| Build hangs at "fetching pnpm" | Conference Wi-Fi blocking npmjs.org | Use a phone hotspot, or distribute a pre-built image via `docker save`/`docker load` |
| `port is already allocated` | Something is on 3100 already | Pick a different host port: `-p 3200:3100`, then point curl at `:3200`. The server still listens on 3100 inside the container. |

> **Note on the `DEDI_RECORD_EXISTS` rows above.** The `DEDI_RECORD_EXISTS`
> error code and its `hint` response field are introduced by [PR #620](https://github.com/nfh-trust-labs/opencred/pull/620).
> If you're running an older server build, the same 409 surfaces as the
> generic `DEDI_CLIENT_ERROR` (no `hint` field) — the underlying cause
> and the fix are identical, only the code name changes.

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

# Issuer DID (strip the #fragment off the verification-method id)
ISSUER_DID="$(curl -s http://localhost:3100/v1/keys \
  -H "Authorization: Bearer $OPENCRED_API_KEY" | jq -r '.keys[0].id | split("#")[0]')"

# Issue
curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"schemaId":"functional-identity/v1","issuerDid":"'"$ISSUER_DID"'",
       "credentialSubject":{"name":"Jane Doe","role":"Bootcamp Attendee",
       "validFrom":"2026-04-26T00:00:00Z"},
       "validFrom":"2026-04-26T00:00:00Z","proofFormat":"vc-jwt"}' \
  | tee credential.json | jq

# Verify (vc-jwt: send the compact JWS string)
jq -n --arg c "$(jq -r '.credential.proof.jwt' credential.json)" '{credential: $c}' \
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
