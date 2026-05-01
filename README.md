# image-policy-provider

OPA Gatekeeper [external-data provider](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata)
that verifies container image signatures with [Cosign](https://docs.sigstore.dev/cosign/overview/).
Used by the CI/CD Security course (Lecture 12) to demonstrate how Gatekeeper
delegates trust decisions about image content to a service running inside the
cluster.

## What it checks

For each image reference Gatekeeper sends in a `ProviderRequest`, the service
runs three checks:

1. **Digest pinning** — the reference must be `repo@sha256:<64hex>`. Tags are
   rejected because they are mutable.
2. **Registry allowlist** — the repo must start with one of the prefixes in
   `ALLOWED_REGISTRIES`.
3. **Cosign signature** — `cosign verify` must succeed against the configured
   trust material (key file, or keyless identity + OIDC issuer).

If any check fails the corresponding `items[].error` is populated and Gatekeeper
denies the request.

## API

Single endpoint `POST /validate` consuming the upstream Gatekeeper schema:

```json
{
  "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
  "kind": "ProviderRequest",
  "request": { "keys": ["ghcr.io/example/app@sha256:..."] }
}
```

## Configuration

| env | default | meaning |
| --- | --- | --- |
| `ALLOWED_REGISTRIES` | `ghcr.io/kse-bd8338bbe006` | comma-separated repo prefixes |
| `COSIGN_KEY_PATH` | unset | path to a Cosign public key (key-based mode) |
| `COSIGN_IDENTITY` | unset | expected signer identity (keyless mode) |
| `COSIGN_OIDC_ISSUER` | unset | expected OIDC issuer (keyless mode) |
| `LOG_LEVEL` | `INFO` | uvicorn / app log level |
| `LOG_BODIES` | unset | when `true`, dump the full `ProviderRequest` / `ProviderResponse` JSON on each admission. Off by default; flip on for teaching / debugging. |

TLS is terminated by uvicorn using the cert files at `/etc/tls/tls.{crt,key}`,
which cert-manager mounts from a `Certificate` issued by the in-cluster Vault
PKI `ClusterIssuer`.

## Local development

```sh
pip install -r requirements-dev.txt
pytest
uvicorn src.main:app --reload
```
