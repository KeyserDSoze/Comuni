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

variable "tenant_proof_key_id" {
  description = "Version of the HMAC tenant proof signer; empty means legacy compatibility. Provision and authorize this ID in PostgreSQL BEFORE switching API replicas."
  type        = string
  default     = ""
  validation {
    condition     = var.tenant_proof_key_id == "" || can(regex("^[a-z][a-z0-9_-]{0,31}$", var.tenant_proof_key_id))
    error_message = "tenant_proof_key_id must be blank or 1-32 lowercase ASCII letters, numbers, underscores or hyphens, starting with a letter."
  }
}

variable "tenant_proof_key" {
  description = "Random secret of 32+ UTF-8 bytes shared by the API signer and PostgreSQL verifier, provisioned after EF migration. Rotate together."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.tenant_proof_key) >= 32
    error_message = "tenant_proof_key must be at least 32 characters."
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
