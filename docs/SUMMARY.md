# Table of contents

* [OpenCred Documentation](README.md)

## Concepts

* [Concepts overview](concepts/README.md)
* [Verifiable Credentials](concepts/verifiable-credentials.md)
* [DIDs](concepts/dids.md)
  * [Per-key registry model](concepts/dids.md#per-key-registry--the-opencred-key-registry-model)
  * [Key lifecycle (active / rotated / revoked)](concepts/dids.md#key-lifecycle--three-states)
  * [did.json snapshot on each key record](concepts/dids.md#didjson-snapshot-on-each-key-record-and-the-two-path-model)
  * [Riverside University worked example](concepts/dids.md#worked-example--riverside-university)
* [Trust chains](concepts/trust-chains.md)
* [Credential support matrix](concepts/support-matrix.md)
* [Revocation](concepts/revocation.md)
  * [Key revocation vs per-credential revocation](concepts/revocation.md#key-revocation-vs-per-credential-revocation)
  * [No DeDi status available — credential is still VALID](concepts/revocation.md#the-no-dedi-status-available-case--credential-stays-valid)

## Desktop App

* [Desktop overview](desktop/README.md)
* [Installation](desktop/installation.md)
* [Getting started](desktop/getting-started.md)
* [Key management](desktop/key-management.md)
  * [Publishing a key to DeDi](desktop/key-management.md#publishing-a-key-to-dedi)
  * [Rotating a key](desktop/key-management.md#rotating-a-key)
  * [Revoking a key](desktop/key-management.md#revoking-a-key)
* [Issuing credentials](desktop/issuing-credentials.md)
* [Verifying credentials](desktop/verifying-credentials.md)
* [Settings and logging](desktop/settings-and-logging.md)
* [Release signing status](desktop/release-signing.md)

## Docker Image

* [Docker overview](docker/README.md)
* [Deployment](docker/deployment.md)
  * [Key lifecycle: publish, rotate, revoke](docker/deployment.md#key-lifecycle--publish-rotate-revoke)
* [API reference](docker/api-reference.md)
  * [Per-key registry endpoints](docker/api-reference.md#per-key-registry-opencred-key-registry-endpoints)
  * [POST /v1/keys/publish](docker/api-reference.md#post-v1keyspublish)
  * [POST /v1/keys/rotate](docker/api-reference.md#post-v1keysrotate)
  * [POST /v1/keys/revoke](docker/api-reference.md#post-v1keysrevoke)
  * [POST /v1/keys/resolve](docker/api-reference.md#post-v1keysresolve-per-key-registry)
* [CLI reference](docker/cli-reference.md)
* [Verifying credentials](docker/verifying-credentials.md)
* [Cloud HSM](docker/cloud-hsm.md)
* [Observability](docker/observability.md)
* [OID4VCI](docker/oid4vci.md)
* [Grafana dashboards](observability/grafana-dashboards/README.md)

## Bootcamp

* [Bootcamp overview](bootcamp/README.md)
* [Local Docker track](bootcamp/local-docker.md)
* [GCP VM track](bootcamp/gcp-vm.md)

## Security

* [Security overview](security/README.md)
* [Threat model](security/threat-model.md)
* [Key handling](security/key-handling.md)
* [Invariants](security/invariants.md)

## Developer Guide

* [Developer overview](development/README.md)
* [Package layout](development/package-layout.md)
* [Building](development/building.md)
* [Testing](development/testing.md)
