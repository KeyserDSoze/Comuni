#!/usr/bin/env bash
set -euo pipefail

# Only Key Vault version METADATA, not the runtime PostgreSQL connection value.
# The container app uses the exact version inside a NEW candidate-only ACA secret.
# Never use az keyvault secret show, print a URI or enable shell tracing.
if [[ $# -ne 2 || ! "$1" =~ ^[a-z][a-z0-9-]{2,23}$ ||
      ! "$2" =~ ^[a-fA-F0-9]{32}$ ]]; then
  echo "Runtime PostgreSQL stage rejected: invalid vault/version metadata." >&2
  exit 2
fi
vault_name="$1"
secret_version="$2"
secret_uri="https://${vault_name}.vault.azure.net/secrets/postgres-runtime-connection/${secret_version}"
query="[?id=='${secret_uri}'].attributes.enabled | [0]"

if ! enabled="$(az keyvault secret list-versions \
    --vault-name "$vault_name" \
    --name postgres-runtime-connection \
    --query "$query" --output tsv 2>/dev/null)"; then
  echo "Runtime PostgreSQL Key Vault metadata unavailable; stage blocked." >&2
  exit 1
fi
if [[ "${enabled,,}" != "true" ]]; then
  echo "Pinned runtime PostgreSQL secret is not enabled; stage blocked." >&2
  exit 1
fi
echo "Pinned runtime PostgreSQL Key Vault metadata checked (no secret values)."
