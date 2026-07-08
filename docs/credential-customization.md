# Credential Customization

OpenCred supports issuer branding on packaged credentials. Customization options control colors, logos, and display names applied when rendering credentials into visual formats (PDF, QR with SVG templates).

## Customization Fields

The `TemplateCustomization` interface is defined in `packages/templates/src/types.ts`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `primaryColor` | string | No | Primary color for the credential. Must be a 6-digit hex color (e.g. `#1a56db`). Used as the main accent color in rendered templates. |
| `logoDataUri` | string | No | Issuer's logo as a data URI. Must start with `data:image/` (e.g. `data:image/png;base64,iVBORw0KGgo...`). Remote URLs are not accepted -- data URIs only (prevents SSRF). |
| `issuerDisplayName` | string | No | Human-readable display name for the issuer. Overrides the DID in rendered templates. Maximum 200 characters. |

### Validation Rules

The server validates customization fields via a Zod schema (`customizationSchema` in `apps/server/src/routes/credentials.ts`):

- `primaryColor` must match the regex `^#[0-9a-fA-F]{6}$` (exactly 6 hex digits with a `#` prefix).
- `logoDataUri` must start with `data:image/`. This ensures only data URIs are accepted, preventing SSRF attacks from remote URL fetching.
- `issuerDisplayName` is capped at 200 characters.
- The entire `customization` object is optional. When omitted, default styling is applied.

## Usage via the Server API

### With POST /v1/credentials/issue

Include a `customization` object in the issue request alongside `packageFormats`:

```bash
curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "schemaId": "functional-identity/v1",
    "issuerDid": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
    "credentialSubject": {
      "name": "Jane Doe",
      "dateOfBirth": "1990-01-15",
      "nationality": "US"
    },
    "validFrom": "2026-01-01T00:00:00Z",
    "proofFormat": "vc-jwt",
    "packageFormats": ["pdf", "qr-png"],
    "customization": {
      "primaryColor": "#1a56db",
      "logoDataUri": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
      "issuerDisplayName": "Acme University"
    }
  }'
```

The customization is applied to any packaged outputs (PDF, QR with SVG template). The signed credential itself is not affected -- customization is a rendering concern only.

Customization only applies when `packageFormats` is specified and the credential is not a compact token (SD-JWT-VC). Compact tokens cannot be packaged inline.

### With POST /v1/credentials/package

Include `customization` when packaging an already-signed credential:

```bash
curl -s http://localhost:3100/v1/credentials/package \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "credential": {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiableCredential"],
      "issuer": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
      "credentialSubject": {
        "name": "Jane Doe",
        "dateOfBirth": "1990-01-15"
      },
      "proof": {
        "type": "JsonWebSignature2020",
        "jwt": "eyJhbGciOiJFUzI1NiIs..."
      }
    },
    "formats": ["pdf", "qr-svg"],
    "customization": {
      "primaryColor": "#0e7c3a",
      "issuerDisplayName": "Green Energy Corp"
    }
  }'
```

### With POST /v1/credentials/batch

Batch issuance also accepts customization. The same branding is applied to all credentials in the batch:

```bash
curl -s http://localhost:3100/v1/credentials/batch \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "csvContent": "name,degree,institution\nJane Doe,MSc,MIT\nJohn Smith,PhD,Stanford",
    "schemaId": "education/v1",
    "issuerDid": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
    "validFrom": "2026-01-01T00:00:00Z",
    "customization": {
      "primaryColor": "#8b5cf6",
      "issuerDisplayName": "Ivy League Consortium"
    }
  }'
```

## Usage via Desktop App

In the Desktop app, customization is configured through the Branding Settings UI:

1. Open **Settings** from the sidebar.
2. Navigate to the **Branding** section.
3. Set your organization's primary color using the color picker.
4. Upload your logo (the app converts it to a data URI automatically).
5. Enter your display name.

These settings are applied to all credentials issued from the desktop app and persist across sessions.

## Template Rendering

The `packages/templates` package handles credential rendering. Templates are SVG-based with `{{placeholder}}` tokens that are substituted at render time.

The `RenderOptions` interface combines customization with render values:

```
RenderOptions
  customization?: TemplateCustomization  (colors, logo, display name)
  values: RenderValues                   (issuer name, title, dates, subject fields, QR code)
```

The rendering pipeline:

1. Select the SVG template matching the schema ID (or use the default template).
2. Apply `primaryColor` to accent elements in the SVG.
3. Insert the `logoDataUri` into the logo placeholder.
4. Replace `issuerDisplayName` in the issuer name field (falls back to the DID if not set).
5. Substitute credential subject fields, dates, and the QR code data URI.

## Security Notes

- **Data URIs only.** The `logoDataUri` field accepts only `data:image/...` URIs. Remote URLs (e.g. `https://example.com/logo.png`) are rejected at the Zod validation layer. This prevents SSRF attacks where a server-side request could be made to an attacker-controlled URL during credential rendering.
- **No executable content.** SVG templates are rendered server-side. User-supplied values are escaped before substitution to prevent SVG injection.
- **Customization does not affect the credential itself.** Branding is applied only to the visual rendering (PDF, QR, SVG). The signed Verifiable Credential payload is not modified by customization -- it remains cryptographically verifiable regardless of rendering options.

## Color Reference

Some example primary colors for common use cases:

| Use Case | Color | Hex |
|----------|-------|-----|
| Government / official | Blue | `#1a56db` |
| Education | Purple | `#8b5cf6` |
| Healthcare | Teal | `#0d9488` |
| Energy | Green | `#0e7c3a` |
| Finance | Dark blue | `#1e3a5f` |
| Corporate | Gray | `#374151` |
