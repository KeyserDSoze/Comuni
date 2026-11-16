variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "prefix" {
  description = "Globally unique short lowercase prefix (e.g. comuni-itn-001)"
  type        = string
  default     = "comuni-itn-001"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{3,17}$", var.prefix))
    error_message = "prefix must be 4-18 lowercase alphanumeric/hyphen characters."
  }
}

variable "location" {
  description = "Azure region; validate service availability and data residency before production."
  type        = string
  default     = "italynorth"
}

variable "postgres_admin_password" {
  description = "Administrative PostgreSQL credential; never store in Git or plaintext tfvars."
  type        = string
  sensitive   = true
}

variable "postgres_runtime_password" {
  description = "Separate least-privileged PostgreSQL runtime role password; provision role after EF migrations."
  type        = string
  sensitive   = true
}

# Metadata only: key bytes are not passed to Terraform.
# A versioned URI avoids uncoordinated latest-version restarts across app revisions.
variable "stable_tenant_proof_secret_version" {
  description = "Existing immutable Key Vault secret version used by the stable 100-percent revision. Cannot be changed during candidate staging."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-fA-F0-9]{32}$", var.stable_tenant_proof_secret_version))
    error_message = "stable_tenant_proof_secret_version must be a 32-character hexadecimal version."
  }
}

variable "stable_revision_suffix" {
  description = "Existing active production Container App revision suffix that must retain 100 percent of traffic during staging."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$", var.stable_revision_suffix)) && !strcontains(var.stable_revision_suffix, "--")
    error_message = "stable_revision_suffix must be a valid existing ACA revision suffix (2-32 lowercase alphanumeric/hyphen chars)."
  }
}

variable "candidate_revision_suffix" {
  description = "Unique suffix of the new 0-percent traffic revision; supplied from the immutable Git commit."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^r[a-z0-9]{12}$", var.candidate_revision_suffix)) && var.candidate_revision_suffix != var.stable_revision_suffix
    error_message = "candidate_revision_suffix must be r followed by 12 lowercase alphanumeric chars and differ from stable_revision_suffix."
  }
}

variable "tenant_proof_secret_version" {
  description = "Required 32-hex Key Vault version of tenant-proof-key installed externally and paired with tenant_proof_key_id."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-fA-F0-9]{32}$", var.tenant_proof_secret_version))
    error_message = "tenant_proof_secret_version must be the explicit 32-character hexadecimal Azure Key Vault secret version."
  }
}

variable "tenant_proof_key_id" {
  description = "Required non-legacy HMAC tenant signing key ID. Provision and authorize its paired key in PostgreSQL BEFORE staging a new API revision."
  type        = string
  nullable    = false
  validation {
    condition     = var.tenant_proof_key_id != "legacy" && can(regex("^[a-z][a-z0-9_-]{0,31}$", var.tenant_proof_key_id))
    error_message = "tenant_proof_key_id must be an explicit non-legacy ID of 1-32 lowercase ASCII letters, numbers, underscores or hyphens, beginning with a letter."
  }
}

variable "authentication_authority" {
  description = "Trusted OIDC issuer base URL (HTTPS) for JWT validation; must be provisioned separately."
  type        = string
  validation {
    condition     = startswith(var.authentication_authority, "https://")
    error_message = "authentication_authority must be an HTTPS URL."
  }
}

variable "authentication_audience" {
  description = "API resource audience expected in trusted OIDC access tokens."
  type        = string
  validation {
    condition     = length(trimspace(var.authentication_audience)) > 0
    error_message = "authentication_audience must not be empty."
  }
}

# All four non-secret browser OAuth values must be configured together.
# Leaving them empty DISABLES the browser login: never fall back to demo JWT in Production.
variable "authentication_browser_client_id" {
  description = "OIDC public SPA client identifier (not a secret); empty until provider registration."
  type        = string
  default     = ""
}

variable "authentication_browser_authorization_endpoint" {
  description = "Trusted HTTPS OIDC authorization endpoint from provider metadata."
  type        = string
  default     = ""
}

variable "authentication_browser_token_endpoint" {
  description = "Trusted HTTPS OIDC token endpoint allowing CORS for the SPA redirect origin."
  type        = string
  default     = ""
}

variable "authentication_browser_scope" {
  description = "OIDC scope list: openid + a delegated API scope; no offline_access."
  type        = string
  default     = ""
}

variable "image" {
  description = "Fully qualified immutable container image, e.g. registry.azurecr.io/comuni:<commit-sha>"
  type        = string
}

variable "tags" {
  type = map(string)
  default = {
    project     = "Comuni"
    managed_by  = "Terraform"
    environment = "development"
  }
}


// Platform inventory is opt-in and disabled on both API and Terraform by
// default. This is VERSION METADATA ONLY; never give a connection string or
// password to Terraform, the state, tfvars or GitHub workflows.
variable "platform_inventory_enabled" {
  description = "Explicitly stage the read-only global Superadmin inventory on the 0%-traffic candidate. Requires separate DB role and a pinned Key Vault connection secret."
  type        = bool
  default     = false
  nullable    = false
  validation {
    condition     = !var.platform_inventory_enabled || can(regex("^[0-9a-fA-F]{32}$", var.platform_inventory_secret_version))
    error_message = "Enabling platform inventory requires an approved 32-hex Key Vault secret version."
  }
}

variable "platform_inventory_secret_version" {
  description = "Optional explicit version metadata for Key Vault secret platform-inventory-connection, provisioned outside Terraform. Empty when inventory is disabled."
  type        = string
  default     = ""
  nullable    = false
  validation {
    condition     = var.platform_inventory_secret_version == "" || can(regex("^[0-9a-fA-F]{32}$", var.platform_inventory_secret_version))
    error_message = "platform_inventory_secret_version must be empty or a 32-hex pinned Key Vault version."
  }
}
