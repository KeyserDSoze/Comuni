#!/usr/bin/env bash
set -euo pipefail

# Only check the enabled flag. Do not fetch, print, or log tenant-proof-key value.
if [[ $# -ne 1 || ! "$1" =~ ^[a-z][a-z0-9-]{2,23}$ ]]; then
  echo "Expected a valid Azure Key Vault name." >&2
  exit 2
fi

vault_name="$1"
# This secret is managed outside Terraform. A missing, inaccessible, or disabled
# secret must prevent terraform plan/apply, rather than deploying a broken API.
if ! enabled="$(az keyvault secret show \
    --vault-name "$vault_name" \
    --name tenant-proof-key \
    --query attributes.enabled \
    --output tsv 2>/dev/null)"; then
  echo "Tenant proof signing secret metadata unavailable in Key Vault; deployment blocked." >&2
  exit 1
fi

if [[ "$enabled" != "true" ]]; then
  echo "Tenant proof signing secret is not enabled in Key Vault; deployment blocked." >&2
  exit 1
fi

echo "External tenant proof secret exists and is enabled (metadata only)."
