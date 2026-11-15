#!/usr/bin/env bash
set -euo pipefail

# Metadata-only preflight of the EXTERNALLY provisioned platform inventory
# connection string secret. Never use 'secret show', versionless latest, or
# print the value/URI. The managed identity reads it only inside ACA.
if [[ $# -ne 2 || ! "$1" =~ ^[a-z][a-z0-9-]{2,23}$ ||
      ! "$2" =~ ^[a-fA-F0-9]{32}$ ]]; then
  echo "Platform inventory stage rejected: invalid Key Vault name/version metadata." >&2
  exit 2
fi

vault_name="$1"
secret_version="$2"
secret_uri="https://${vault_name}.vault.azure.net/secrets/platform-inventory-connection/${secret_version}"
query="[?id=='${secret_uri}'].attributes.enabled | [0]"

# 'list-versions' returns metadata only. Suppress Azure CLI errors because
# external error messages can contain identifiers from operator inputs.
if ! enabled="$(az keyvault secret list-versions \
    --vault-name "$vault_name" \
    --name platform-inventory-connection \
    --query "$query" --output tsv 2>/dev/null)"; then
  echo "Platform inventory Key Vault metadata unavailable; stage blocked." >&2
  exit 1
fi
if [[ "${enabled,,}" != "true" ]]; then
  echo "Pinned platform inventory secret not enabled; stage blocked." >&2
  exit 1
fi
echo "Pinned platform inventory Key Vault metadata checked (no secret values)."
