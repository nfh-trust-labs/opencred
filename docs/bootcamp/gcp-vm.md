# OpenCred Bootcamp — GCP VM track

> **Goal**: have an OpenCred Docker container running on a Google Compute Engine VM **you own**, issue a signed Verifiable Credential against it from your laptop over an SSH tunnel, verify it, then tear the VM down.
>
> **Time**: ~90 minutes hands-on + ~30 min GCP setup + **15 min mandatory teardown** when you're done.
>
> **Prereqs**: same Unix-shell comfort as the local bootcamp, **plus** a Google Cloud account with billing enabled. No prior GCE / IAM experience required.

A few notes before you start:

- **Same OpenCred story, different host.** This is the local-bootcamp curriculum with a GCE VM swapped in for the laptop. You still own the key and the container. NFH Trust Labs still sees nothing.
- **Tunnel, don't expose.** OpenCred is a signing oracle. Do not open port 3100 to the internet, even with an API key set. The whole guide assumes you `gcloud compute ssh` with a port forward and `curl localhost:3100` from your laptop. §7d shows the production-shape alternative (reverse proxy + TLS + IP allowlist), but that is opt-in.
- **Cost is real but small.** An `e2-small` VM is roughly $0.02/hour. A full bootcamp + a forgotten VM weekend is still under a dollar. But **don't forget the teardown step** — Section 9 is the most important section in this guide.
- **Use `us-central1` (or your nearest cheap region)** unless you have a reason to pick differently. Cheaper, lower latency from most places, and the docs assume that region for naming examples.

The convention in the commands below: `LOCAL$` is your laptop, `VM$` is the GCE VM (after you SSH into it).

---

### 1. Pre-flight

#### 1a. Tools on your laptop

| Tool | Why | Check |
|---|---|---|
| `gcloud` CLI | Create and SSH into the VM | `gcloud --version` |
| `curl` | Hit the OpenCred API through the tunnel | `curl --version` |
| `jq` (optional) | Pretty-print JSON | `jq --version` |
| `ssh` | Underneath `gcloud compute ssh` | `ssh -V` |
| **Postman** (optional alternative to curl) | Pre-built collection of every API request | <https://www.postman.com/downloads/> |

You do **not** need Docker on your laptop for this track. Docker runs on the
VM, not locally.

> **Postman or curl — pick whichever you prefer.** Every API request in §6
> onwards is provided in two forms: a copy-pasteable `curl` in this guide,
> and an equivalent in [`postman-collection.json`](postman-collection.json)
> (sibling file in this directory; download the raw JSON). The Postman
> collection's default `baseUrl` is `http://localhost:3100`, which is
> exactly where your SSH port-forward will surface the VM's container — so
> the same collection works for both tracks. **Import → drop the file →
> set the `apiKey` collection variable**, then jump in.

Install gcloud:

- **macOS**: `brew install --cask google-cloud-sdk`, or follow <https://cloud.google.com/sdk/docs/install>
- **Linux**: `curl https://sdk.cloud.google.com | bash` and re-source your shell, or use the apt/yum package
- **Windows**: download the installer from <https://cloud.google.com/sdk/docs/install>; run all OpenCred commands from PowerShell or WSL

Then authenticate and pick a project:

```
LOCAL$ gcloud auth login
LOCAL$ gcloud auth application-default login   # for ADC, used later by Cloud KMS
LOCAL$ gcloud projects list
LOCAL$ gcloud config set project YOUR_PROJECT_ID
LOCAL$ gcloud config set compute/region us-central1
LOCAL$ gcloud config set compute/zone us-central1-a
```

#### 1b. GCP account state

- Billing is **enabled** on the project. Free-tier alone won't cover egress
  during the bootcamp, but the total cost is cents. Check:
  ```
  LOCAL$ gcloud billing projects describe YOUR_PROJECT_ID
  ```
- The Compute Engine API is **enabled**:
  ```
  LOCAL$ gcloud services enable compute.googleapis.com
  ```
- (Stretch) For the Cloud KMS demo in §7, also enable:
  ```
  LOCAL$ gcloud services enable cloudkms.googleapis.com
  ```

If `gcloud compute instances list` runs without errors and prints "Listed 0
items" (or your existing VMs), you are ready.

### 2. Create the VM

We'll use a small Debian 12 VM. `e2-small` is plenty.

```
LOCAL$ gcloud compute instances create opencred-bootcamp \
  --machine-type=e2-small \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --zone=us-central1-a \
  --boot-disk-size=20GB \
  --metadata=enable-oslogin=TRUE \
  --tags=opencred-bootcamp \
  --no-address \
  --no-service-account --no-scopes
```

A few notes on what those flags mean and why:

- `--no-address` means the VM has no external IP. We will reach it through
  Identity-Aware Proxy (IAP) instead. This keeps your VM off the public
  internet entirely.
- `--no-service-account --no-scopes` means the VM has no GCP credentials at
  all. We'll add them only for the Cloud KMS stretch in §7. Default-deny is
  the right starting point.
- `--metadata=enable-oslogin=TRUE` lets you SSH in with your Google identity
  rather than managing SSH keys by hand.

Allow IAP-tunneled SSH to anything tagged `opencred-bootcamp`:

```
LOCAL$ gcloud compute firewall-rules create opencred-allow-iap-ssh \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges=35.235.240.0/20 \
  --target-tags=opencred-bootcamp
```

(That source range is GCP's published IAP egress range.)

You should now see:

```
LOCAL$ gcloud compute instances list
NAME                ZONE           MACHINE_TYPE  STATUS
opencred-bootcamp   us-central1-a  e2-small      RUNNING
```

### 3. SSH in and install Docker

```
LOCAL$ gcloud compute ssh opencred-bootcamp --tunnel-through-iap
```

That puts you on the VM. From here, prompts are `VM$`.

```
VM$ sudo apt-get update
VM$ curl -fsSL https://get.docker.com | sudo sh
VM$ sudo usermod -aG docker $USER
VM$ exit                                  # log out so the group change takes effect
```

Reconnect:

```
LOCAL$ gcloud compute ssh opencred-bootcamp --tunnel-through-iap
VM$ docker run hello-world                 # should print "Hello from Docker!"
```

Also install the small set of tools we'll need on the VM:

```
VM$ sudo apt-get install -y git openssl jq
```

### 4. Generate the key and pull the image

All of this happens **on the VM**, not on your laptop.

> **No source-repo clone required.** The main flow pulls the public OpenCred
> image from GHCR (a few subsections down). The `nfh-trust-labs/opencred`
> source repo is private; `git clone` returns 404 for most readers. If you
> want to inspect or modify the server before issuing, see the optional
> "Building from source" callout right after the `docker pull` step.

Generate a signing key. EC P-256 supports all three proof formats:

```
VM$ mkdir -p ~/keys
VM$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -out ~/keys/issuer-key.pem
VM$ chmod 600 ~/keys/issuer-key.pem
```

Generate an API token. Save it — you'll paste it into curl from your laptop:

```
VM$ openssl rand -base64 32
# Copy the output; you'll need it on both the VM and your laptop.
```

Set it as an env var on the VM:

```
VM$ export OPENCRED_API_KEY="paste-the-token-here"
```

#### 4a. (Optional) DeDi credentials on the VM

If you have DeDi access and want to use the revocation + public-key registry features later in §7b / §7c, export the access details on the VM. **Skip this entire block if you don't have DeDi access** — every other section works without DeDi, and `/v1/health` will simply report `dediConfigured: false`.

```
VM$ export OPENCRED_DEDI_BASE_URL="https://your-dedi-instance.example.org"
VM$ export OPENCRED_DEDI_AUTH_TYPE="api-key"
VM$ export OPENCRED_DEDI_API_KEY="paste-your-token-here"
VM$ export OPENCRED_DEDI_NAMESPACE="your-namespace-id"
```

> **What goes in `OPENCRED_DEDI_NAMESPACE`?** Use the namespace ID issued to you by your DeDi operator. The format depends on whether your namespace is verified:
>
> - **Unverified namespace** → looks like `did:web:did.cord.network:xyz` — the DeDi instance's own did:web with your ID appended. This is the default when the operator provisions a new namespace without a domain-ownership challenge.
> - **Verified namespace** → looks like `xyz.org` — your own domain, used directly as the namespace ID after you've proved ownership to the DeDi operator.
>
> Use whichever value the operator gave you. Both work identically with OpenCred; only the DID resolution path that verifiers walk differs.

The OpenCred container's startup hook will create your namespace and
the four registries inside it (`vc-revocation-registry`,
`public_key_registry`, `schema_registry`, `context_registry`) on first
boot — no pre-provisioning required.

> **Schema-collision caveat.** Pre-existing registries are only safe to
> reuse when their attached schema matches what OpenCred writes. DeDi
> backends ship built-in JSON Schemas for some registry names — notably
> `public_key.json` with shape `{public_key_id, publicKey, keyType, …}`,
> which is **not** the shape OpenCred writes (`{did, document?,
> keyStatus}` — `document` is omitted for `did:key` records, and
> `keyStatus` is `"current"` or `"rotated"`). If a DeDi operator
> pre-creates a `public_key_registry` with the built-in schema before
> OpenCred boots, every `/v1/keys/publish` call will fail with a `400
> "Record data does not match the registry schema"`. Let OpenCred create
> the registries on first boot to avoid this; see local-docker.md §3a for
> the full mitigation note.

Pull the public OpenCred image. ~30 seconds on a GCP VM:

```
VM$ docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
VM$ docker tag  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest opencred:bootcamp
```

> **About the image URL.** The `nfh-trust-labs/opencred` segment is the source
> repo's GHCR namespace, not a visibility hint — GHCR namespaces every
> container under the repo that publishes it, so the image inherits the source
> repo's name even though the image itself is **public** and anonymously
> pullable. You do not need access to the source repo to pull. If `docker
> pull` is asking for credentials, run `docker logout ghcr.io` first to clear
> any stale tokens in `~/.docker/config.json` and retry.

When it finishes:

```
VM$ docker images opencred:bootcamp        # should show one row
```

> **Building from source instead?** Optional — only do this if you want to inspect or patch the server before issuing. The source repo `nfh-trust-labs/opencred` is private; `git clone` returns 404 unless you have read access. If you do:
>
> ```
> VM$ git clone https://github.com/nfh-trust-labs/opencred.git
> VM$ cd opencred && git checkout new-opencred-dev
> VM$ docker build -f apps/server/Dockerfile -t opencred:bootcamp .
> ```
>
> That's ~5–10 minutes on an `e2-small` (don't try on `e2-micro` — see the troubleshooting matrix). Pulling the public image is faster; for the bootcamp it's strictly better.

### 5. Run the container, tunnel from your laptop

Run, with the same hardening flags as the local guide. The
`"${DEDI_ENV[@]}"` placeholder expands to the env-var block built by
the preamble above. If you skipped §4a the array is empty and the
container starts in DeDi-disabled mode with no edits.

```
VM$ # Conditionally build the DeDi env-var block. Empty if you skipped the
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
      -e OPENCRED_KEY_LABEL=gcp-bootcamp-issuer \
      -e OPENCRED_LOG_LEVEL=info \
      -v "$HOME/keys/issuer-key.pem:/secrets/issuer-key.pem:ro" \
      "${DEDI_ENV[@]}" \
      --read-only \
      --tmpfs /tmp:noexec,nosuid,size=64m \
      --cap-drop ALL \
      --security-opt no-new-privileges:true \
      opencred:bootcamp
```

Tail the logs to confirm startup and key load:

```
VM$ docker logs -f opencred
# Ctrl-C once you see "OpenCred server listening" and a fingerprint.
```

The container is now listening on `127.0.0.1:3100` **on the VM**. The VM has
no external IP and the firewall doesn't allow inbound 3100. To reach it from
your laptop, open a second terminal on your laptop and SSH-tunnel:

```
LOCAL$ gcloud compute ssh opencred-bootcamp --tunnel-through-iap \
         -- -N -L 3100:localhost:3100
```

Leave that terminal open — it's holding the tunnel. From a third terminal on
your laptop, hit the API as if it were local:

```
LOCAL$ export OPENCRED_API_KEY="paste-the-same-token-here"
LOCAL$ curl -s http://localhost:3100/v1/health | jq
```

You want:

```
{
  "status": "ok",
  "ready": true,
  "signingKeyLoaded": true,
  "dediConfigured": false,
  "timestamp": "..."
}
```

(`dediConfigured` will be `true` if you completed §4a and `false`
otherwise. Both are fine for the core flow.)

If the curl hangs forever, the tunnel didn't establish — check the SSH
window for errors. If the response is `503` with `signingKeyLoaded: false`,
the key file isn't readable inside the container — check the `-v` mount path.

### 6. Issue and verify your first credential

The flow is identical to the local bootcamp once the tunnel is up.

> **Postman users**: with the SSH tunnel from §5 running, the Postman
> collection's default `baseUrl=http://localhost:3100` reaches your VM's
> container exactly the same way. Click `GET /v1/keys` (auto-saves
> `issuerDid`), then `POST /v1/credentials/issue (vc-jwt)`
> (auto-saves `lastCredential`), then `POST /v1/credentials/verify`. The
> curl examples below are the same calls in shell form.

```
# The /v1/keys response gives the verification-method id (DID#fragment);
# strip the fragment to get the bare DID expected by the issue endpoint.
LOCAL$ ISSUER_DID="$(curl -s http://localhost:3100/v1/keys \
        -H "Authorization: Bearer $OPENCRED_API_KEY" | jq -r '.keys[0].id | split("#")[0]')"
LOCAL$ echo "$ISSUER_DID"

LOCAL$ curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"schemaId\": \"functional-identity/v1\",
    \"issuerDid\": \"$ISSUER_DID\",
    \"credentialSubject\": {
      \"name\": \"Jane Doe\",
      \"role\": \"GCP Bootcamp Attendee\",
      \"validFrom\": \"2026-04-27T00:00:00Z\"
    },
    \"validFrom\": \"2026-04-27T00:00:00Z\",
    \"validUntil\": \"2027-04-27T00:00:00Z\",
    \"proofFormat\": \"vc-jwt\"
  }" | tee credential.json | jq .credential

# vc-jwt verification: send the compact JWS string (the .proof.jwt value)
# as the `credential` field. For data-integrity / sd-jwt-vc, see the
# proof-format notes below for the matching input shapes.
LOCAL$ jq -n --arg c "$(jq -r '.credential.proof.jwt' credential.json)" '{credential: $c}' | \
  curl -s http://localhost:3100/v1/credentials/verify \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" \
    -d @- | jq
```

`vc-jwt` is the server's default and works with every bundled schema. Repeat the issue call with `"proofFormat": "data-integrity"` or `"proofFormat": "sd-jwt-vc"` (and `selectiveDisclosureClaims: ["/credentialSubject/role"]` for the latter) to see the other two formats; `data-integrity` requires a JSON-LD context that does not redefine W3C-protected terms, otherwise the server returns `CRYPTO_ERROR`.

The tamper test is the same — flip a byte of `credentialSubject.name` and
re-verify. `valid: true` becomes `valid: false`.

> **PDF inputs.** `POST /v1/credentials/verify` also accepts a raw
> PDF body when the request carries `Content-Type: application/pdf`.
> Useful when you've already packaged a credential as a printable
> PDF and want to verify it directly without re-extracting the JSON.
> See [Docker → API reference → `POST /v1/credentials/verify`](../docker/api-reference.md#post-v1credentialsverify).

#### 6a. Issue against your own pasted schema

The 34 bundled schemas cover common cases. To issue a credential shaped
like *your* domain (training certificate, role badge, equipment licence,
…), pass `inlineSchema` in the request body — no fork or rebuild required.

```bash
LOCAL$ curl -s http://localhost:3100/v1/credentials/issue \
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
      \"course\": \"GCP Bootcamp 101\",
      \"passedOn\": \"2026-04-27\",
      \"score\": 95
    },
    \"validFrom\": \"2026-04-27T00:00:00Z\",
    \"proofFormat\": \"vc-jwt\"
  }" | jq
```

The server compiles the inline schema, validates `credentialSubject`
against it, and writes the schema's `$id` (or a base64 data-URI fallback)
into the credential's `credentialSchema` block. When both `schemaId` and
`inlineSchema` are present, the inline schema wins.

For `data-integrity` proofs you also need an `inlineContext` (JSON-LD
context document) — without one, RDFC-1.0 safe mode rejects undefined
terms. `vc-jwt` and `sd-jwt-vc` work out of the box.

#### 6c. Package the credential as a PDF / QR code

Two paths:

**A. Inline at issue time.** Add `packageFormats` (and optional
`customization`) to the issue request body and the response includes
`packagedOutputs[]` alongside the signed credential. Postman:
**Issue & Verify → POST /v1/credentials/issue (vc-jwt +
inline package)**.

**B. Separate `POST /v1/credentials/package` request.** Same
`customization` block; pre-request script in
**Packaging → POST /v1/credentials/package** picks up whatever
the last issue request returned (object for data-integrity / vc-jwt,
compact string for sd-jwt-vc).

#### Works with all three proof formats

| `proofFormat` | `credential` shape in the request | What the QR encodes |
|---|---|---|
| `data-integrity` | JSON-LD VC object | Bare PixelPass-compressed VC JSON (no prefix) |
| `vc-jwt` | JSON-LD VC object (JWT inside `proof.jwt`) | Same |
| `sd-jwt-vc` | Compact `~`-separated string | The raw token, embedded verbatim |

For `sd-jwt-vc`, the server decodes the JWT payload offline (no signature
verification — packaging is a rendering step) to drive the PDF layout,
and embeds the original token verbatim into the QR so any verifier
scanning it runs a real cryptographic check against your public key.

#### Output formats

| `format` | `mimeType` | `encoding` | `data` |
|---|---|---|---|
| `qr-png` | `image/png` | `utf-8` ⚠️ | `data:image/png;base64,<...>` data URL |
| `qr-svg` | `image/svg+xml` | `utf-8` | Inline SVG XML |
| `pdf` | `application/pdf` | `base64` | Pure base64 |
| `json` | `application/json` | `utf-8` | Pretty-printed VC, or `{"format":"sd-jwt-vc","credential":"<token>"}` |

#### Decoding the response on your laptop

Save the Postman response, then on your laptop (not the VM):

```bash
LOCAL$ jq -r '.outputs[]
              | select(.format=="qr-png")
              | .data
              | sub("^data:image/png;base64,"; "")' response.json \
       | base64 -d > qr.png
LOCAL$ jq -r '.outputs[] | select(.format=="pdf")    | .data' response.json | base64 -d > certificate.pdf
LOCAL$ jq -r '.outputs[] | select(.format=="qr-svg") | .data' response.json > qr.svg
LOCAL$ jq -r '.outputs[] | select(.format=="json")   | .data' response.json > credential.json
LOCAL$ open certificate.pdf qr.png qr.svg
```

(For the inline path, replace `.outputs[]` with `.packagedOutputs[]`.)

#### Customization

Optional fields under `customization`:

| Field | Type | What it does |
|---|---|---|
| `primaryColor` / `secondaryColor` / `textColor` / `labelColor` / `backgroundColor` | hex `#rrggbb` | Certificate colors |
| `issuerDisplayName` | string ≤200 | Replaces the issuer DID under "ISSUED BY" — **must be this exact key** (`issuerName` is silently dropped) |
| `logoDataUri` / `sealDataUri` | data URI | Image embedded in the certificate |
| `logoWidth` / `logoHeight` | int 10–200 | Logo dimensions |
| `footerText` | string ≤500 | Pass `""` to suppress the disclaimer footer entirely |

#### Per-format failures

If one format fails (e.g. QR data > QR capacity), the failure appears
in `errors[]` with the format + message — the rest still come back,
HTTP stays `200 OK`.

#### 6d. Try a different built-in schema: `electricity/v1`

`functional-identity/v1` is intentionally minimal. The bundled
registry has 34 others — `GET /v1/schemas` lists them all. The
`electricity/v1` schema (a Beckn-flavored utility-customer credential)
is a good worked example because it hits two friction points first-time
attendees often miss.

```bash
LOCAL$ curl -s http://localhost:3100/v1/credentials/issue \
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
    \"validFrom\": \"2026-04-27T00:00:00Z\",
    \"validUntil\": \"2027-04-27T00:00:00Z\",
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
`storageProfile` are all optional.

### 7. Stretch goals

#### 7a. GCP Cloud KMS — the real reason to be on GCP

This is the demo that actually exploits being on a cloud VM. Instead of a
file on disk, the signing key lives in Cloud KMS and the container only ever
holds a permission to *use* it.

Create a key ring and an EC P-256 key (do this from your laptop):

```
LOCAL$ gcloud kms keyrings create opencred --location=global

LOCAL$ gcloud kms keys create opencred-issuer \
  --location=global \
  --keyring=opencred \
  --purpose=asymmetric-signing \
  --default-algorithm=ec-sign-p256-sha256
```

Get the resource name including version (you'll pass this in env):

```
LOCAL$ KMS_KEY="$(gcloud kms keys versions list \
  --location=global --keyring=opencred --key=opencred-issuer \
  --format='value(name)' | head -n1)"
LOCAL$ echo "$KMS_KEY"
# projects/.../locations/global/keyRings/opencred/cryptoKeys/opencred-issuer/cryptoKeyVersions/1
```

Give the VM's identity permission to sign with it. Because we created the VM
with no service account, the cleanest move is to attach a minimal one now:

```
LOCAL$ gcloud iam service-accounts create opencred-sa \
  --display-name="OpenCred bootcamp signer"

LOCAL$ SA="opencred-sa@$(gcloud config get-value project).iam.gserviceaccount.com"

LOCAL$ gcloud kms keys add-iam-policy-binding opencred-issuer \
  --location=global \
  --keyring=opencred \
  --member="serviceAccount:$SA" \
  --role=roles/cloudkms.signerVerifier

LOCAL$ gcloud compute instances stop opencred-bootcamp
LOCAL$ gcloud compute instances set-service-account opencred-bootcamp \
  --service-account="$SA" \
  --scopes=cloud-platform
LOCAL$ gcloud compute instances start opencred-bootcamp
```

Then on the VM, swap the file-based key for the KMS one:

```
VM$ docker rm -f opencred
VM$ docker run -d \
      --name opencred \
      -p 3100:3100 \
      -e OPENCRED_API_KEY="$OPENCRED_API_KEY" \
      -e OPENCRED_KMS_PROVIDER=gcp \
      -e OPENCRED_GCP_KMS_KEY_NAME="projects/.../cryptoKeyVersions/1" \
      -e OPENCRED_KEY_LABEL=gcp-kms-issuer \
      --read-only --cap-drop ALL --security-opt no-new-privileges:true \
      opencred:bootcamp
```

Re-tunnel from your laptop, hit `/v1/keys` — you'll see `source: "gcp-kms"`
and a fresh `did:key:...` derived from the KMS public key. Issue a credential
the same way you did in §6. The signature was computed inside KMS and the
private key never touched the VM.

#### 7b. DeDi (revocation)

If you completed §4a, your container is already DeDi-configured. Confirm:

```
LOCAL$ curl -s http://localhost:3100/v1/health | jq .dediConfigured
# => true
```

If `dediConfigured` is `false`, you skipped §4a. To enable now:

```
VM$ export OPENCRED_DEDI_BASE_URL="https://your-dedi-instance.example.org"
VM$ export OPENCRED_DEDI_AUTH_TYPE="api-key"
VM$ export OPENCRED_DEDI_API_KEY="paste-your-token-here"
VM$ export OPENCRED_DEDI_NAMESPACE="your-namespace-id"   # see §4a for format
VM$ docker rm -f opencred
VM$ # Re-run §5 — the same docker run command picks up the new env vars.
```

The full revoke + revocation-status flow is in §7c of the local guide
(`BOOTCAMP.md`); the curl examples are identical except `localhost:3100`
on your laptop reaches the VM through the SSH tunnel.

#### 7c. DeDi public-key registry — publish your DID document

With DeDi configured (§7b), you can push a DID document to the
`public_key_registry` and resolve it back. OpenCred's verifier tries the
canonical `did:web` HTTPS endpoint first and falls back to DeDi when the
well-known URL is unreachable, so this lets you stop hosting your own
`.well-known/did.json` and let DeDi serve as the discovery layer for
DeDi-aware verifiers.

```bash
# Publish (POST body: { did, document, namespace? })
LOCAL$ curl -s http://localhost:3100/v1/keys/publish \
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

# Resolve (POST body: { did, namespace? })
LOCAL$ curl -s http://localhost:3100/v1/keys/resolve \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "did": "did:web:bootcamp.example.org" }' | jq
```

Both endpoints return `503 DEDI_NOT_CONFIGURED` until DeDi is wired up.
The same `rejectKeyMaterial` defense-in-depth guard runs over the request
body — a `privateKey` field anywhere in the payload, or a string starting
with `-----BEGIN ... PRIVATE KEY-----`, fails 400 before anything reaches
DeDi.

#### 7d. Public TLS endpoint (only do this if you actually need one)

If you need a real `https://...` URL — for instance, to hook OpenCred up to a wallet — add a reverse proxy with TLS and an IP allowlist. Outline only:

1. Reserve a static external IP and assign it to the VM.
2. Open ports 80/443 with a firewall rule restricted to your own public IP (`curl ifconfig.me` on your laptop).
3. Point a DNS A record at the IP. Cloud DNS works; so does any registrar.
4. Run the bundled `nginx` block in `docker-compose.yml` (already includes
   `proxy_pass http://server:3100`, security headers, and a TLS template),
   plus `caddy` or `certbot` for Let's Encrypt.
5. **Keep `OPENCRED_API_KEY` set.** TLS authenticates the channel; the API
   key still authenticates the caller.

Most bootcamp runs don't need this. The IAP tunnel is enough for everything in §5–§6.

#### 7e. Mid-session DeDi: ensure a namespace at runtime

If the running container is DeDi-configured but you want to bootstrap
a fresh namespace without restarting the VM container, hit the
runtime endpoint over the IAP tunnel:

```bash
LOCAL$ curl -sS -X POST http://localhost:3100/v1/dedi/namespace/ensure \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -d '{"namespace":"did:web:my-tenant.example.org"}' | jq
```

Returns `{ namespace, registries: [...4 names...] }` on success. The
endpoint is idempotent — re-calling it for an already-ensured
namespace returns the same shape with `200 OK`. Returns
`503 DEDI_NOT_CONFIGURED` if the container was launched without the
four `OPENCRED_DEDI_*` env vars; in that case you need to
`docker rm && docker run` with them set (see §5/§6 for the env-var
block).

The Postman collection has this under **DeDi runtime → POST
/v1/dedi/namespace/ensure**.

### 7h. Beyond the bootcamp — production hardening

The VM track drives a single container with the most ergonomic
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
| `gcloud compute ssh ... --tunnel-through-iap` returns `Permission denied` | IAP API not enabled, or no IAM permission on the VM | `gcloud services enable iap.googleapis.com` and grant your user `roles/iap.tunnelResourceAccessor` on the project |
| `gcloud compute instances create` fails with `Quota 'CPUS' exceeded` | New project quota | Request a quota bump (5 min) or pick a smaller machine type — `e2-micro` works |
| `docker build` runs out of memory on the VM | `e2-micro` is too small | If you're building from source, recreate the VM as `e2-small` (or larger) — pnpm + tsc want ~1.5 GB. Or skip the build and `docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest` instead, which works on `e2-micro`. |
| `docker pull ghcr.io/...` returns `unauthorized` | Stale GHCR creds in `~/.docker/config.json` | The image is public — `docker logout ghcr.io` and retry the pull |
| Tunnel works but `/v1/health` hangs | Container not listening on 3100, or `-p 3100:3100` was forgotten | `docker ps` to confirm port mapping; `docker logs opencred` to see startup errors |
| `/v1/health` returns `503 signingKeyLoaded: false` | Key path wrong, or `node` user can't read the file inside the container | Confirm `~/keys/issuer-key.pem` exists with `0600`; the `-v` source path must be absolute |
| `401 AUTHENTICATION_ERROR` from your laptop | The token on the laptop side doesn't match the token in the container's env | Re-export `OPENCRED_API_KEY` on both sides from the same source-of-truth |
| `503 DEDI_NOT_CONFIGURED` | DeDi env vars not set or partial | See §7b; `dediConfigured` in `/v1/health` is the canonical check |
| Container exits with `OPENCRED_API_KEY is required` | Forgot to pass it through `-e` | Re-run `docker run` with `-e OPENCRED_API_KEY="$OPENCRED_API_KEY"` |
| Startup log shows DeDi lookup URL with `%E2%80%9C` / `%E2%80%9D` wrapping your namespace (e.g. `/dedi/lookup/%E2%80%9Cverifaistudio.co%E2%80%9D` → `404 Namespace not found` → `401 Invalid API key`) | `OPENCRED_DEDI_NAMESPACE` (or API key) was pasted with **Unicode smart quotes** (`"…"` not ASCII `"…"`) — usually from a chat app or notes that auto-corrects | Re-export with straight ASCII quotes, or none if the value has no spaces: `export OPENCRED_DEDI_NAMESPACE=verifaistudio.co`. Verify with `printf '%s\n' "$OPENCRED_DEDI_NAMESPACE" \| od -c \| head -1` — anything other than plain ASCII bytes means a smart quote slipped in. |
| Cloud KMS issuance returns `403 PERMISSION_DENIED` | VM's service account lacks `roles/cloudkms.signerVerifier` | See §7a binding step; remember to stop/restart the VM after attaching the SA |
| Mysterious `connection refused` on the tunnel even with the SSH window open | Tunnel terminal got backgrounded and SSH timed out | Foreground that terminal, or use `gcloud compute start-iap-tunnel ... &` with `keepalive` |

### 9. Mandatory teardown

Run these before you close out the bootcamp. **A forgotten VM is a billing surprise** — don't skip this section.

```
LOCAL$ gcloud compute instances delete opencred-bootcamp \
  --zone=us-central1-a --quiet

LOCAL$ gcloud compute firewall-rules delete opencred-allow-iap-ssh --quiet
```

If you did §7a (Cloud KMS), also clean those up:

```
LOCAL$ gcloud kms keys versions destroy 1 \
  --location=global --keyring=opencred --key=opencred-issuer

LOCAL$ gcloud iam service-accounts delete \
  "opencred-sa@$(gcloud config get-value project).iam.gserviceaccount.com" \
  --quiet
```

(KMS key rings can't be deleted, only emptied. That's fine — empty key rings
cost nothing.)

If you did §7d (TLS endpoint), also release the static IP:

```
LOCAL$ gcloud compute addresses delete opencred-static --region=us-central1 --quiet
```

Confirm everything is gone:

```
LOCAL$ gcloud compute instances list           # should be empty
LOCAL$ gcloud compute firewall-rules list      # opencred rules absent
LOCAL$ gcloud kms keys list --location=global --keyring=opencred  # destroyed version only
```

---

## Appendix A — One-screen quick-reference card

```
# One-time setup, on laptop
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud config set compute/zone us-central1-a
gcloud services enable compute.googleapis.com

# Create VM (no public IP, no SA)
gcloud compute instances create opencred-bootcamp \
  --machine-type=e2-small --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=20GB --metadata=enable-oslogin=TRUE \
  --tags=opencred-bootcamp --no-address \
  --no-service-account --no-scopes

gcloud compute firewall-rules create opencred-allow-iap-ssh \
  --direction=INGRESS --action=ALLOW --rules=tcp:22 \
  --source-ranges=35.235.240.0/20 --target-tags=opencred-bootcamp

# SSH (with port forward in a second terminal)
gcloud compute ssh opencred-bootcamp --tunnel-through-iap \
  -- -N -L 3100:localhost:3100

# On the VM
sudo apt-get update && curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && exit          # reconnect
sudo apt-get install -y git openssl jq

docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
docker tag  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest opencred:bootcamp

mkdir -p ~/keys
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ~/keys/issuer-key.pem
chmod 600 ~/keys/issuer-key.pem
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

docker run -d --name opencred -p 3100:3100 \
  -e OPENCRED_API_KEY="$OPENCRED_API_KEY" \
  -e OPENCRED_KEY_PATH=/secrets/issuer-key.pem \
  -v "$HOME/keys/issuer-key.pem:/secrets/issuer-key.pem:ro" \
  "${DEDI_ENV[@]}" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  opencred:bootcamp

# On laptop, through the tunnel
export OPENCRED_API_KEY="paste-the-same-token"
curl -s http://localhost:3100/v1/health | jq
ISSUER_DID="$(curl -s http://localhost:3100/v1/keys \
  -H "Authorization: Bearer $OPENCRED_API_KEY" | jq -r '.keys[0].id | split("#")[0]')"
# Issue/verify exactly as in the local bootcamp

# Teardown — don't forget
gcloud compute instances delete opencred-bootcamp --zone=us-central1-a --quiet
gcloud compute firewall-rules delete opencred-allow-iap-ssh --quiet
```

---

## Appendix B — When to pick this track over the local one

| Situation | Track |
|---|---|
| You can run Docker locally | **Local** — fewer moving parts |
| Your laptop is corporate-locked or low-spec | **GCP** |
| You want to try GCP Cloud KMS as the signer | **GCP** |
| You need a real `https://` URL by the end (e.g., for a wallet) | **GCP** + §7d |
| You want to avoid any cloud bill | **Local** |
| You only have 90 minutes | **Local** |

---

## Appendix C — Pointers into the repo

| What | Where |
|---|---|
| Server source | `apps/server/src/` |
| Dockerfile | `apps/server/Dockerfile` |
| Config + env-var Zod schema | `apps/server/src/config.ts` |
| Cloud HSM wiring | `apps/server/src/signing/cloud-hsm/` |
| Reference Cloud Run deploy script | `deploy/cloud-run/deploy.sh` |
| Reference VM + systemd setup | `deploy/vm/setup.sh`, `deploy/vm/opencred.service` |
| Reverse-proxy config (commented in `docker-compose.yml`) | `deploy/nginx.conf` |
| Full Docker docs | `docs/docker/` |
| Top-level deployment guide | `docs/deployment-guide.md` |
