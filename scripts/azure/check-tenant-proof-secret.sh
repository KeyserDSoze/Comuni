#!/usr/bin/env bash
set -euo pipefail

# Inspect ONLY the enabled metadata of the exact approved version. Never use
# latest/versionless: Container Apps may refresh latest and restart active replicas.
# Never fetch, print or log the actual tenant signing key value.
if [[ $# -ne 2 || ! "$1" =~ ^[a-z][a-z0-9-]{2,23}$ ||
      ! "$2" =~ ^[a-fA-F0-9]{32}$ ]]; then
  echo "Expected an Azure Key Vault name and an explicit 32-hex secret version." >&2
  exit 2
fi

vault_name="$1"
secret_version="$2"
secret_uri="https://${vault_name}.vault.azure.net/secrets/tenant-proof-key/${secret_version}"

# The deploy identity needs permission to query metadata; no secret value in output.
# list-versions uses the metadata-only Key Vault endpoint (secrets/list permission).
# In contrast, secret show retrieves a secret object that also contains its value.
# The exact full URI is matched; do not allow a later/latest version as fallback.
query="[?id=='${secret_uri}'].attributes.enabled | [0]"
if ! enabled="$(az keyvault secret list-versions --vault-name "$vault_name" --name tenant-proof-key --query "$query" --output tsv 2>/dev/null)"; then
  echo "Pinned tenant proof signing secret metadata unavailable; deployment blocked." >&2
  exit 1
fi

if [[ "${enabled,,}" != "true" ]]; then
  echo "Pinned tenant proof signing secret is not enabled; deployment blocked." >&2
  exit 1
fi

echo "Pinned tenant proof signing secret exists and is enabled (metadata only)."
