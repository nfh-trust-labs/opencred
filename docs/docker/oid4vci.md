# OID4VCI (OpenID for Verifiable Credential Issuance)

> **Status: Not yet implemented.** OID4VCI endpoints are not present in the current OpenCred server. This page documents the planned protocol flow for future reference. The feature is tracked on GitHub Issues.

OID4VCI support will allow the OpenCred Docker deployment to act as a Credential Issuer under the OID4VCI specification, supporting the **pre-authorized code** grant type. When implemented, it will run entirely in your infrastructure.

## Planned Endpoints

The following endpoints are planned but **not yet available** in the current codebase:

- `GET /.well-known/openid-credential-issuer` -- issuer metadata
- `POST /oid4vci/token` -- token endpoint for pre-authorized code grant
- `POST /oid4vci/credential` -- credential issuance with proof-of-possession
- `POST /oid4vci/offers` -- internal API for creating credential offers

## Credential Formats (Planned)

| Format | OID4VCI Identifier | Description |
|--------|--------------------|-------------|
| SD-JWT-VC | `dc+sd-jwt` | Selective Disclosure JWT Verifiable Credential |
| JWT VC JSON | `jwt_vc_json` | Standard JWT-based Verifiable Credential |

## Current Alternative

For credential issuance, use the existing `POST /v1/credentials/issue` endpoint. See the [API reference](api-reference.md) for details.
