# Issuing Credentials

## Single Credential Issuance

1. Select a schema from the Home screen (built-in template or custom)
2. Fill in the credential subject fields
3. Configure issuance settings:
   - **Signing Key** -- select from imported/generated keys
   - **Valid From** -- defaults to today
   - **Valid Until** -- defaults to 1 year from today
4. Click **Build & Sign**

The result card shows the signed credential with export options.

## Built-in Schemas

| Schema | Required Fields |
|--------|----------------|
| Education | name, degree, institution, dateConferred |
| Employment | name, employer, position, startDate |
| Identity | name, dateOfBirth, nationality, documentNumber |
| Health | name, certification, issuingBody, validUntil |
| Business | name, registrationNumber, jurisdiction, incorporationDate |

All schemas accept additional properties beyond the required fields.

## Custom Schemas

Two ways to add a custom schema:

- **Fetch from URL** -- enter a JSON Schema URL and it will be imported
- **Manual definition** -- define fields when creating a blank credential; the schema is saved automatically for reuse

Custom schemas appear on the Home screen alongside built-in templates. They can be renamed or deleted via hover actions.

## Proof Formats

| Format | Output | Selective Disclosure | Algorithm Support |
|--------|--------|---------------------|-------------------|
| `vc-jwt` (default) | JSON-LD with embedded JWT proof | No | All (ECDSA, Ed25519, RSA) |
| `data-integrity` | JSON-LD with Data Integrity proof | No | ECDSA (P-256, P-384), Ed25519 only |
| `sd-jwt-vc` | Compact SD-JWT token | Yes | All (ECDSA, Ed25519, RSA) |

## Batch Issuance

Issue up to 1,000 credentials from a CSV file.

### Workflow

1. **Upload CSV** -- native file dialog, auto-detects delimiter (comma, semicolon, tab)
2. **Map Columns** -- map CSV columns to schema fields; auto-detects matching column names
3. **Configure** -- set validity dates, signing key, output formats (JSON, PDF, QR), and proof format
4. **Process** -- progress bar with per-row status (success, error, skipped)
5. **Export** -- download all results as a ZIP file

### Row Limit

Maximum 1,000 rows per CSV. Split larger datasets into multiple files.

## Export Formats

| Format | Description |
|--------|-------------|
| JSON | Full signed credential as JSON-LD |
| PDF | Formatted credential document |
| QR Code | PNG image encoding the credential |

Export options appear on the credential result card and in the credential history detail modal.

The PDF certificate's **Credential Details** section renders the full
`credentialSubject` tree — nested objects and arrays of objects (e.g. a
utility credential's `customerProfile.installationAddress.country`) are
expanded into indented sub-rows, one leaf per row, rather than being
collapsed to a single value. Arrays of plain values are shown comma-joined
on one line.

## Credential History

Issued credentials are saved locally (capped at 100 entries). View them from the Home screen under **Recent Credentials**. Each entry shows the schema name, subject summary, and issuance date. Click to view full details, re-export, or reissue.
